//! Exact immutable loader records retained by the same BMI/mission owner.
//! No registry-name reopen can replace executable or calibration authority.
use crate::firmware_asset::Asset;
use alloc::{sync::Arc, vec::Vec};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read, Write};
use narf_firmware::{FirmwareBlob, FirmwareError, FirmwareRegistry};
use narf_lib::sync::IrqSafeSpinLock;
const MAX_SOURCES: usize = 8;
pub(super) fn invoke<T>(
    source: Option<&Source>,
    operation: impl FnOnce() -> T,
) -> Result<T, FirmwareError> {
    match source {
        Some(s) => s.invoke(operation),
        None => {
            #[cfg(any(test, feature = "kernel-test"))]
            {
                Ok(operation())
            }
            #[cfg(not(any(test, feature = "kernel-test")))]
            {
                let _ = operation;
                Err(FirmwareError::AuthorityRevoked)
            }
        }
    }
}
struct Records {
    assets: Vec<Arc<Asset>>,
    image: bool,
    board: bool,
    sealed: bool,
    pci: Option<Cap<BusDeviceCap, Write>>,
}
#[derive(Clone)]
pub(super) struct Source {
    registry: Cap<FirmwareRegistry, Read>,
    records: Arc<IrqSafeSpinLock<Records>>,
}
impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kImmutableSource")
            .finish_non_exhaustive()
    }
}
struct Step<'a, T> {
    assets: &'a [Option<Arc<Asset>>],
    operation: &'a mut dyn FnMut() -> T,
}
struct PciStep<F>(F);
impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for PciStep<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
impl<T> CapOp<FirmwareBlob, Read> for Step<'_, T> {
    type Output = Result<T, FirmwareError>;
    fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
        Ok(walk(self.assets, self.operation))
    }
}
fn walk<T>(
    assets: &[Option<Arc<Asset>>],
    operation: &mut dyn FnMut() -> T,
) -> Result<T, FirmwareError> {
    let Some((first, rest)) = assets.split_first() else {
        return Ok(operation());
    };
    let Some(first) = first else {
        return walk(rest, operation);
    };
    first
        .cap
        .invoke(Step {
            assets: rest,
            operation,
        })
        .map_err(|_| FirmwareError::AuthorityRevoked)?
}
impl Source {
    pub fn new(registry: Cap<FirmwareRegistry, Read>) -> Self {
        Self {
            registry,
            records: Arc::new(IrqSafeSpinLock::new(Records {
                assets: Vec::new(),
                image: false,
                board: false,
                sealed: false,
                pci: None,
            })),
        }
    }
    pub fn bind_pci(&self, cap: Cap<BusDeviceCap, Write>) -> Result<(), FirmwareError> {
        cap.invoke(NoopOp)
            .map_err(|_| FirmwareError::AuthorityRevoked)?;
        let mut r = self.records.lock();
        if r.sealed || r.pci.is_some() {
            return Err(FirmwareError::BadFormat);
        }
        r.pci = Some(cap);
        Ok(())
    }
    pub fn retain(&self, asset: Asset, image: bool, board: bool) -> Result<(), FirmwareError> {
        self.registry
            .invoke(NoopOp)
            .map_err(|_| FirmwareError::AuthorityRevoked)?;
        if !asset.current() {
            return Err(FirmwareError::AuthorityRevoked);
        }
        let mut r = self.records.lock();
        if r.sealed || r.assets.len() == MAX_SOURCES {
            return Err(FirmwareError::BadFormat);
        }
        r.assets
            .try_reserve(1)
            .map_err(|_| FirmwareError::OutOfMemory)?;
        r.assets.push(Arc::new(asset));
        r.image |= image;
        r.board |= board;
        Ok(())
    }
    pub fn seal(&self) -> Result<(), FirmwareError> {
        {
            let mut r = self.records.lock();
            if r.sealed || !r.image || !r.board {
                return Err(FirmwareError::BadFormat);
            }
            r.sealed = true;
        }
        self.check()
    }
    pub fn check(&self) -> Result<(), FirmwareError> {
        self.invoke(|| ())
    }
    pub fn invoke<T>(&self, operation: impl FnOnce() -> T) -> Result<T, FirmwareError> {
        if !self.records.lock().sealed {
            return Err(FirmwareError::BadFormat);
        }
        self.invoke_boot(operation)
    }
    pub fn invoke_boot<T>(&self, operation: impl FnOnce() -> T) -> Result<T, FirmwareError> {
        // Drop the loader lock before invoking anything: stack callbacks may
        // synchronously send ARP/ND through this same radio/source.
        let (snapshot, pci): ([Option<Arc<Asset>>; MAX_SOURCES], _) = {
            let r = self.records.lock();
            (core::array::from_fn(|i| r.assets.get(i).cloned()), r.pci)
        };
        struct RegistryStep<'a, T>(Step<'a, T>);
        impl<T> CapOp<FirmwareRegistry, Read> for RegistryStep<'_, T> {
            type Output = Result<T, FirmwareError>;
            fn execute(self, _: &Cap<FirmwareRegistry, Read>) -> Result<Self::Output, CapError> {
                Ok(walk(self.0.assets, self.0.operation))
            }
        }
        let mut operation = Some(operation);
        let mut call = || {
            let operation = operation.take().unwrap();
            match pci {
                Some(cap) => cap
                    .invoke(PciStep(operation))
                    .map_err(|_| FirmwareError::AuthorityRevoked),
                None => Ok(operation()),
            }
        };
        self.registry
            .invoke(RegistryStep(Step {
                assets: &snapshot,
                operation: &mut call,
            }))
            .map_err(|_| FirmwareError::AuthorityRevoked)??
    }
}

#[cfg(feature = "kernel-test")]
pub(super) type FixtureSources = (Source, [Cap<FirmwareBlob, Read>; 2]);
#[cfg(feature = "kernel-test")]
pub(super) fn fixture() -> Result<FixtureSources, &'static str> {
    use super::firmware::Files;
    const IMAGE: &str = "ath10k/narf-source-fixture/firmware-6.bin";
    const BOARD: &str = "ath10k/narf-source-fixture/board.bin";
    let (write, read) = narf_firmware::bootstrap_authority();
    // Inert signed inputs prove current-source ownership in the native
    // transport model. They are not a deployable executable/calibration.
    crate::firmware_asset::tests::install(&write, IMAGE, b"inert native image source", true)
        .map_err(|_| "source image install")?;
    crate::firmware_asset::tests::install(&write, BOARD, b"inert native board source", true)
        .map_err(|_| "source board install")?;
    let mut files = super::firmware::RegistryFiles::with_authority(read);
    files
        .source()
        .bind_pci(Cap::<BusDeviceCap, Write>::bootstrap())
        .map_err(|_| "fixture PCI cap binding")?;
    if files.load(IMAGE).map_err(|_| "source image copy")? != b"inert native image source"
        || files.load(BOARD).map_err(|_| "source board copy")? != b"inert native board source"
    {
        return Err("native source immutable bytes changed");
    }
    files.seal().map_err(|_| "source seal")?;
    let source = files.source();
    let caps = {
        let r = source.records.lock();
        [r.assets[0].cap, r.assets[1].cap]
    };
    Ok((source, caps))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_ath10k_signed_source_exact_bytes_digest_and_revocation_are_retained() -> TestResult {
        (|| {
            for index in 0..2 {
                let (source, caps) = fixture()?;
                {
                    let r = source.records.lock();
                    for asset in &r.assets {
                        // Registry's historical `sha256` field is BLAKE3;
                        // retain its exact native digest, never relabel it.
                        if asset.signer.is_none()
                            || asset.digest != narf_crypto::blake3_hash(&asset.bytes)
                        {
                            return Err("retained signed source bytes/digest changed");
                        }
                    }
                }
                let mut calls = 0;
                source
                    .invoke(|| calls += 1)
                    .map_err(|_| "live exact source invoke")?;
                caps[index].revoke();
                if source.invoke(|| calls += 1).is_ok() || calls != 1 {
                    return Err("revoked actual executable/BDF reached current operation");
                }
                // A fresh canonical-name asset and capability cannot relabel
                // the old owner. Its exact revoked record remains terminal.
                let (replacement, _) = fixture()?;
                replacement.check().map_err(|_| "fresh source fixture")?;
                if source.invoke(|| calls += 1).is_ok() || calls != 1 {
                    return Err("source reinstall resurrected an old native owner");
                }
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/source",
        smoke_ath10k_signed_source_exact_bytes_digest_and_revocation_are_retained
    );
    fn smoke_ath10k_source_snapshot_drops_loader_lock_before_reentrant_publication() -> TestResult {
        (|| {
            let (source, _) = fixture()?;
            source
                .invoke(|| {
                    if source.records.try_lock().is_none() {
                        return Err("loader lock retained through publication");
                    }
                    source
                        .invoke(|| ())
                        .map_err(|_| "reentrant source publication")
                })
                .map_err(|_| "outer source invoke")??;
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/source",
        smoke_ath10k_source_snapshot_drops_loader_lock_before_reentrant_publication
    );
    fn smoke_ath10k_source_retains_exact_pci_epoch_and_rejects_late_rebinding() -> TestResult {
        (|| {
            let (source, _) = fixture()?;
            let cap = source.records.lock().pci.ok_or("source PCI cap missing")?;
            let next = Cap::<BusDeviceCap, Write>::bootstrap();
            if source.bind_pci(next).is_ok() {
                return Err("sealed native source was rebound to a successor PCI grant");
            }
            cap.revoke();
            let mut ran = false;
            if source.invoke(|| ran = true).is_ok() || ran {
                return Err("native publication escaped revoked retained PCI epoch");
            }
            Ok(())
        })()
        .map_or_else(TestResult::Fail, |()| TestResult::Pass)
    }
    kernel_test_in!(
        "drivers/wireless/ath10k/source",
        smoke_ath10k_source_retains_exact_pci_epoch_and_rejects_late_rebinding
    );
}
