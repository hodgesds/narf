// SPDX-License-Identifier: GPL-2.0-or-later
//! Sealed original native host + actual Controller/Card lifetime receipt.
//! Identity/currentness only: no RF, interface, key or DATA grant follows.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::sync::IrqSafeSpinLock;

/// Nonreviving original-owner lifetime. Retirement and final copy share this
/// fixed gate; no native waits or caller callbacks occur under its guard.
pub(crate) struct Lifetime(IrqSafeSpinLock<bool>);
impl core::fmt::Debug for Lifetime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioOwnerLifetime").finish_non_exhaustive()
    }
}
impl Lifetime {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(IrqSafeSpinLock::new(true)))
    }
    pub(crate) fn current(&self) -> bool {
        *self.0.lock()
    }
    pub(crate) fn retire(&self) {
        *self.0.lock() = false;
    }
}

#[derive(Clone)]
enum Native {
    Pci {
        cap: Cap<BusDeviceCap, Write>,
        device: BusDevice,
        live: Arc<Lifetime>,
        intx: Arc<AtomicBool>,
    },
    #[cfg(any(test, feature = "kernel-test"))]
    Fixture(Arc<Lifetime>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Retired,
    Authority,
    Identity,
}
/// Constructors and lifetime attachment are private to the host package.
/// A caller-supplied validator/counter or observed BDF cannot create this.
#[derive(Clone)]
pub struct Source {
    native: Native,
    controller: Option<Arc<Lifetime>>,
    card: Option<Arc<Lifetime>>,
}
impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioOriginalCardSource")
            .field("card_lifetime", &self.card.is_some())
            .finish_non_exhaustive()
    }
}
impl Source {
    pub(crate) fn pci(
        cap: Cap<BusDeviceCap, Write>,
        device: BusDevice,
        live: Arc<Lifetime>,
        intx: Arc<AtomicBool>,
    ) -> Self {
        Self {
            native: Native::Pci {
                cap,
                device,
                live,
                intx,
            },
            controller: None,
            card: None,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn fixture(live: Arc<Lifetime>) -> Self {
        Self {
            native: Native::Fixture(live),
            controller: None,
            card: None,
        }
    }
    pub(crate) fn retain_controller(mut self, live: &Arc<Lifetime>) -> Option<Self> {
        if self.controller.is_some() || !live.current() {
            return None;
        }
        self.controller = Some(live.clone());
        Some(self)
    }
    pub(crate) fn retain_card(mut self, live: &Arc<Lifetime>) -> Option<Self> {
        if self.controller.is_none() || self.card.is_some() || !live.current() {
            return None;
        }
        self.card = Some(live.clone());
        Some(self)
    }
    pub fn current(&self) -> Result<(), Error> {
        self.invoke(|| ())
    }
    /// Kernel-only final fixed publication. Caller has already completed
    /// dynamic callbacks and retains its independent role/source/RX proof.
    /// The closure must only check fixed guards and copy; no provider lookup.
    pub fn invoke<T>(&self, copy: impl FnOnce() -> T) -> Result<T, Error> {
        let controller = self.controller.as_ref().ok_or(Error::Retired)?.0.lock();
        let card = self.card.as_ref().ok_or(Error::Retired)?.0.lock();
        if !*controller || !*card {
            return Err(Error::Retired);
        }
        match &self.native {
            Native::Pci {
                cap,
                device,
                live,
                intx,
            } => {
                let mut live = live.0.lock();
                struct Operation<F>(F);
                impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for Operation<F> {
                    type Output = T;
                    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
                        Ok(self.0())
                    }
                }
                let result = cap
                    .invoke(Operation(|| {
                        if !*live {
                            return Err(Error::Retired);
                        }
                        let identity = narf_bus::pci::read_config32(cap, device, 0)
                            .map_err(|_| Error::Authority)?;
                        let command = narf_bus::pci::read_command(cap, device)
                            .map_err(|_| Error::Authority)?;
                        let expected =
                            u32::from(device.id.vendor) | (u32::from(device.id.device) << 16);
                        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
                        let policy = if intx.load(Ordering::Acquire) {
                            MEM_SPACE
                        } else {
                            MEM_SPACE | INTX_DISABLE
                        };
                        if identity != expected
                            || command == u16::MAX
                            || command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != policy
                        {
                            return Err(Error::Identity);
                        }
                        if !*live {
                            return Err(Error::Retired);
                        }
                        Ok(copy())
                    }))
                    .map_err(|_| Error::Authority)
                    .and_then(|result| result);
                if result.is_err() {
                    // Actual bad native identity/decode/current capability
                    // permanently retires the same original MMIO owner.
                    *live = false;
                }
                result
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Native::Fixture(live) => {
                let live = live.0.lock();
                if !*live {
                    return Err(Error::Retired);
                }
                Ok(copy())
            }
        }
    }
}
