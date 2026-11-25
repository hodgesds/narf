//! The transport's source fence, module build (`runtime_source.rs` built in).
//!
//! Built in, the executable and PNVM stay bound to their revocable firmware
//! registry capabilities, and every register publication re-checks them, the
//! PCI command state and any AP/P2P/regulatory role owner. A module loads
//! firmware through `narf_firmware_open` into a private copy (its manifest
//! `Firmware` cap is the authority, checked by the kernel at open), and it
//! carries no AP/P2P/regulatory roles. What remains to fence is the device:
//! [`Fence::invoke`] runs under the PCI [`super::Authority`], whose KABI calls
//! the kernel checks against the probe token and refuses once teardown has
//! revoked it.
use crate::firmware_asset::Asset;

/// The bound executable/PNVM sources: private copies, nothing to revoke.
#[derive(Clone)]
pub(super) enum Assets {
    Native,
}
impl Assets {
    pub(super) fn bind(_firmware: &Asset, _pnvm: Option<&Asset>) -> Result<Self, &'static str> {
        Ok(Self::Native)
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        operation()
    }
}

/// The current-source fence every publication runs under.
#[derive(Clone)]
pub(in crate::iwlwifi) struct Fence {
    assets: Assets,
    pci: super::Authority,
}
impl Fence {
    pub(super) fn new(assets: Assets, pci: super::Authority) -> Self {
        Self { assets, pci }
    }
    pub(in crate::iwlwifi) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.assets.invoke(|| self.pci.invoke(operation))
    }
    /// No initiating RF receipt exists in the module build (no P2P client).
    pub(in crate::iwlwifi) fn invoke_packet<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        self.invoke(operation)
    }
}
impl super::Hardware {
    pub(in crate::iwlwifi) fn bind_sources(
        &mut self,
        firmware: &Asset,
        pnvm: Option<&Asset>,
    ) -> Result<(), &'static str> {
        if self.armed || self.sources.is_some() {
            return Err("Intel source binding after native startup/rebind");
        }
        self.sources = Some(Assets::bind(firmware, pnvm)?);
        Ok(())
    }
    pub(super) fn source_assets(&self) -> Result<Assets, &'static str> {
        self.sources
            .clone()
            .ok_or("native Intel executable/PNVM source owner absent")
    }
    pub(in crate::iwlwifi) fn source_fence(&self) -> Result<Fence, &'static str> {
        Ok(Fence::new(self.source_assets()?, self.authority(true)))
    }
}
