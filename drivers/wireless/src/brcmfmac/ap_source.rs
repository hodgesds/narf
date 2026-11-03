// SPDX-License-Identifier: GPL-2.0-or-later
//! Original native PCI/firmware ownership retained by a copied AP event.
//! No endpoint lookup, capability grant or arbitrary provider callback occurs
//! at this final boundary. Native register paths retain their own invocation.
use super::{pcie::invoke_registers, provision::Proof, runtime::Error};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

#[derive(Clone)]
enum Owner {
    Pci {
        cap: Cap<BusDeviceCap, Write>,
        proof: Option<Arc<Proof>>,
        device: BusDevice,
    },
    Sdio {
        native: narf_drivers_sdio::source::Source,
        proof: Arc<Proof>,
    },
    #[cfg(any(test, feature = "kernel-test"))]
    Fixture(Arc<AtomicBool>),
}
/// Opaque original native source. Capturing one supplies no RF, key, peer or
/// DATA authority: those belong to the concrete AP role/copy generation.
#[derive(Clone)]
pub struct Source {
    owner: Owner,
    live: Option<Arc<AtomicBool>>,
}
impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacApNativeSource")
            .field("retained_generation", &self.live.is_some())
            .finish_non_exhaustive()
    }
}
impl Source {
    pub(super) fn pci(
        cap: Cap<BusDeviceCap, Write>,
        proof: Option<Arc<Proof>>,
        device: BusDevice,
    ) -> Self {
        Self {
            owner: Owner::Pci { cap, proof, device },
            live: None,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture(present: Arc<AtomicBool>) -> Self {
        Self {
            owner: Owner::Fixture(present),
            live: None,
        }
    }
    /// Raw fixed native SDIO receipt; Runtime attaches its own actual
    /// nonreviving service generation before this can pass current/invoke.
    pub(crate) fn sdio(
        native: narf_drivers_sdio::source::Source,
        proof: Arc<Proof>,
    ) -> Option<Self> {
        proof.validate().ok()?;
        native.current().ok()?;
        Some(Self {
            owner: Owner::Sdio { native, proof },
            live: None,
        })
    }
    pub(crate) fn retain(mut self, live: &Arc<AtomicBool>) -> Self {
        self.live = Some(live.clone());
        self
    }
    pub(crate) fn belongs_to(&self, live: &Arc<AtomicBool>) -> bool {
        self.live.as_ref().is_some_and(|old| Arc::ptr_eq(old, live))
    }
    pub(super) fn same_generation(&self, other: &Self) -> bool {
        self.live
            .as_ref()
            .zip(other.live.as_ref())
            .is_some_and(|(own, other)| Arc::ptr_eq(own, other))
    }
    pub(crate) fn current(&self) -> Result<(), Error> {
        self.invoke(|| ())
    }
    /// The caller has completed dynamic interface/socket callbacks already.
    /// Its closure performs only the final fixed-guard check and actual copy
    /// publication. It must not invoke a provider or recapture an endpoint.
    pub(crate) fn invoke<T>(&self, copy: impl FnOnce() -> T) -> Result<T, Error> {
        let live = self.live.as_ref().ok_or(Error::Access)?;
        if !live.load(Ordering::Acquire) {
            return Err(Error::Failed);
        }
        match &self.owner {
            Owner::Pci { cap, proof, device } => {
                if let Some(proof) = proof {
                    proof.validate().map_err(|_| Error::Access)?;
                }
                invoke_registers(cap, || {
                    let identity =
                        narf_bus::pci::read_config32(cap, device, 0).map_err(|_| Error::Access)?;
                    let command =
                        narf_bus::pci::read_command(cap, device).map_err(|_| Error::Access)?;
                    let expected =
                        u32::from(device.id.vendor) | (u32::from(device.id.device) << 16);
                    let required = narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER;
                    if identity != expected || command == u16::MAX || command & required != required
                    {
                        return Err(Error::Access);
                    }
                    if !live.load(Ordering::Acquire) {
                        Err(Error::Failed)
                    } else {
                        Ok(copy())
                    }
                })
                .map_err(|_| Error::Access)?
            }
            Owner::Sdio { native, proof } => {
                proof.validate().map_err(|_| Error::Access)?;
                native
                    .invoke(|| {
                        if !live.load(Ordering::Acquire) {
                            Err(Error::Failed)
                        } else {
                            Ok(copy())
                        }
                    })
                    .map_err(|_| Error::Access)?
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Owner::Fixture(present) => {
                if !present.load(Ordering::Acquire) || !live.load(Ordering::Acquire) {
                    Err(Error::Access)
                } else {
                    Ok(copy())
                }
            }
        }
    }
}
