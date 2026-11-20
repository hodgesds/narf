// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO reset authority (Linux 7.3-rc4
//! `brcmfmac/sdio.c::brcmf_sdio_bus_reset`): after the stop, `mmc_hw_reset`
//! (`mmc/core/sdio.c::mmc_sdio_hw_reset`: `mmc_power_cycle` then
//! `mmc_sdio_reinit_card`) and the function's re-probe
//! (`brcmf_sdio_probe` -> `brcmf_sdio_firmware_callback`: chip attach,
//! CM3/SOCRAM passive, firmware + NVRAM download, F2 and save-restore
//! setup). Every reboot re-runs the signed board selection and asset load
//! through the retained registry authority, so a revoked or replaced asset
//! refuses the reboot instead of reusing stale bytes. The CLM blob of the
//! last good load is shared with the generation publisher, which replays
//! it in `Station::initialize_live`.
use super::{
    firmware::FirmwareLoader,
    runtime::{Error, Reboot},
    sdio_bridge::SdioTransport,
};
use crate::brcmfmac::provision::{select_using, Assets, Family, Selection};
use alloc::{string::String, sync::Arc, vec::Vec};
use narf_drivers_sdio::{card::Card, pio::HostIdentity, pio::Registers, SdioFunction};

/// CLM blob of the current firmware generation, shared with the publisher.
pub type Clm = Arc<narf_lib::sync::IrqSafeSpinLock<Vec<u8>>>;

/// Signed selection, its assets and the packed NVRAM for one host/card.
pub(super) fn select(
    authority: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    manifest: &str,
    host: HostIdentity,
    function: (u16, u16),
) -> Result<(Selection, Assets, Vec<u8>), &'static str> {
    let selection = select_using(
        authority,
        manifest,
        Family::Sdio43439,
        host,
        Some((1, function.0, function.1)),
    )
    .map_err(|_| "signed CYW43439 host/card board selection unavailable or mismatched")?;
    let assets = selection
        .load_using(authority)
        .map_err(|_| "selected CYW43439 asset signature/key/length/hash mismatch")?;
    // Shared single-board parser rejects generic/multi-device selectors.
    let nvram = crate::brcmfmac::boot::pack_nvram(&assets.nvram)
        .map_err(|_| "invalid selected CYW43439 NVRAM")?;
    Ok((selection, assets, nvram))
}

/// The probe-time boot of one whole card (`brcmf_sdio_probe` through
/// `brcmf_sdio_firmware_callback`): F1 preparation, the signed AI/CM3
/// firmware loader with chip-revision admission, F2/mailbox setup and the
/// save-restore idle sleep.
pub(super) fn boot_card<F: SdioFunction + Send>(
    function: F,
    assets: &Assets,
    nvram: &[u8],
    revisions: u16,
) -> Result<SdioTransport<F>, &'static str> {
    let mut transport = SdioTransport::new(function).qualify(assets.proof.clone());
    transport
        .prepare()
        .map_err(|_| "SDIO F1 preparation failed")?;
    let mut loader = FirmwareLoader::new(transport, &assets.firmware, nvram, 0, false)
        .require_revisions(revisions);
    loader
        .run()
        .map_err(|_| "firmware bootstrap/chip revision failed")?;
    let core = loader.packet_core().ok_or("firmware did not release CM3")?;
    let revision = loader
        .packet_core_revision()
        .ok_or("firmware did not release CM3")?;
    let mut transport = loader
        .into_transport()
        .map_err(|_| "firmware owner not ready")?;
    transport
        .initialize_packets(core)
        .map_err(|_| "F2/mailbox setup failed")?;
    transport
        .initialize_sleep(revision)
        .map_err(|_| "SDIO save-restore setup failed")?;
    Ok(transport)
}

/// Retained reboot authority of one CYW43439 card.
pub struct Reprovision {
    authority: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    manifest: String,
    /// Host and F1 identity of the original probe; a re-enumerated card
    /// must present both again.
    host: HostIdentity,
    function: (u16, u16),
    clm: Clm,
}
impl core::fmt::Debug for Reprovision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CywReprovision")
            .field("host", &self.host)
            .field("function", &self.function)
            .finish_non_exhaustive()
    }
}
impl Reprovision {
    pub(crate) fn new(
        authority: narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
        manifest: &str,
        host: HostIdentity,
        function: (u16, u16),
        clm: Clm,
    ) -> Self {
        Self {
            authority,
            manifest: String::from(manifest),
            host,
            function,
            clm,
        }
    }
}
impl<R: Registers + Send + 'static> Reboot<SdioTransport<Card<R>>> for Reprovision {
    fn boot(&mut self, transport: SdioTransport<Card<R>>) -> Result<SdioTransport<Card<R>>, Error> {
        let mut card = transport.into_function().ok_or(Error::Busy)?;
        // mmc_hw_reset: power cycle + same-card reinit. A card that does
        // not come back (no fresh enumeration, different identity) stays
        // powered off and terminal; it is dropped here.
        SdioFunction::hw_reset(&mut card).map_err(|_| Error::Failed)?;
        let function = card.function(1).map(|f| (f.vendor, f.device));
        if card.host_identity() != Some(self.host) || function != Some(self.function) {
            return Err(Error::Authority);
        }
        let (selection, assets, nvram) =
            select(&self.authority, &self.manifest, self.host, self.function)
                .map_err(|_| Error::Authority)?;
        assets.proof.validate().map_err(|_| Error::Authority)?;
        let transport =
            boot_card(card, &assets, &nvram, selection.revisions()).map_err(|_| Error::Failed)?;
        *self.clm.lock() = assets.clm.clone();
        Ok(transport)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "sdio_reset_tests.rs"]
mod tests;
