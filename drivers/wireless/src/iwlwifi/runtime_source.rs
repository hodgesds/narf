//! Current executable/PNVM authority survives the startup caller. Firmware
//! bytes are private immutable copies; only capability invocation permits I/O
//! or publication. No calibration, country or RF-power permission is created.
use crate::firmware_asset::Asset;
use narf_capabilities::{Cap, CapError, CapOp, Read};
use narf_firmware::FirmwareBlob;

#[derive(Clone)]
pub(super) enum Assets {
    Native {
        firmware: Cap<FirmwareBlob, Read>,
        pnvm: Option<Cap<FirmwareBlob, Read>>,
    },
    #[cfg(any(test, feature = "kernel-test"))]
    Model,
}
struct Live<F>(F);
impl<T, F: FnOnce() -> Result<T, &'static str>> CapOp<FirmwareBlob, Read> for Live<F> {
    type Output = Result<T, &'static str>;
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok((self.0)())
    }
}
fn bind(asset: &Asset) -> Result<Cap<FirmwareBlob, Read>, &'static str> {
    struct Same<'a>(&'a Asset);
    impl CapOp<FirmwareBlob, Read> for Same<'_> {
        type Output = bool;
        fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<bool, CapError> {
            Ok(narf_firmware::view_of(cap).is_ok_and(|view| {
                view.bytes == self.0.bytes
                    && view.sha256 == self.0.digest
                    && view.signer == self.0.signer
            }))
        }
    }
    if !asset
        .cap
        .invoke(Same(asset))
        .map_err(|_| "Intel firmware source revoked during binding")?
    {
        return Err("Intel executable/PNVM source differs from copied native bytes");
    }
    Ok(asset.cap)
}
impl Assets {
    pub(super) fn bind(firmware: &Asset, pnvm: Option<&Asset>) -> Result<Self, &'static str> {
        Ok(Self::Native {
            firmware: bind(firmware)?,
            pnvm: pnvm.map(bind).transpose()?,
        })
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        match self {
            Self::Native { firmware, pnvm } => firmware
                .invoke(Live(|| match pnvm {
                    Some(cap) => cap
                        .invoke(Live(operation))
                        .map_err(|_| "Intel PNVM source authority revoked")?,
                    None => operation(),
                }))
                .map_err(|_| "Intel executable source authority revoked")?,
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Model => operation(),
        }
    }
}
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
    #[cfg(feature = "kernel-test")]
    pub(in crate::iwlwifi) fn revoke_model_pci(&self) {
        assert!(
            !self.pci.native,
            "physical PCI revocation is not a fixture operation"
        );
        self.pci.cap.revoke();
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
        if let Some(assets) = &self.sources {
            return Ok(assets.clone());
        }
        #[cfg(any(test, feature = "kernel-test"))]
        if self.device.id.vendor == 0xffff {
            return Ok(Assets::Model);
        }
        Err("native Intel executable/PNVM source owner absent")
    }
    pub(in crate::iwlwifi) fn source_fence(&self) -> Result<Fence, &'static str> {
        Ok(Fence::new(self.source_assets()?, self.authority(true)))
    }
}

#[cfg(feature = "kernel-test")]
#[path = "runtime_source_tests.rs"]
pub(in crate::iwlwifi) mod tests;
