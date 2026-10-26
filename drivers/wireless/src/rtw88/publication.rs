// SPDX-License-Identifier: GPL-2.0-or-later
//! Read-only retained authority for actual carrier/host frame publication.
//! Unlike a readiness snapshot this encloses the publication in current
//! signed-source and PCI invocations, without retaining device/ring locks.
use super::{firmware_transport::Error, power_policy::Gate};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
#[derive(Clone)]
pub(super) struct Publication {
    gate: Gate,
    native: Option<(BusDevice, Cap<BusDeviceCap, Write>)>,
    receive_epoch: Option<super::station_control::ReceiveEpoch>,
    #[cfg(any(test, feature = "kernel-test"))]
    before: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
    #[cfg(any(test, feature = "kernel-test"))]
    model: Option<
        alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
    >,
}
impl Publication {
    pub(super) fn native(gate: Gate, device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Self {
        Self {
            gate,
            native: Some((device, cap)),
            receive_epoch: None,
            #[cfg(any(test, feature = "kernel-test"))]
            before: None,
            #[cfg(any(test, feature = "kernel-test"))]
            model: None,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn model(
        gate: Gate,
        policy: Option<
            alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
        >,
    ) -> Self {
        Self {
            gate,
            native: None,
            receive_epoch: None,
            before: None,
            model: policy,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn before_invoke(
        mut self,
        hook: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
    ) -> Self {
        self.before = hook;
        self
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.current() {
            return Err(Error::State);
        }
        let operation = || {
            if !self.current() {
                return Err(Error::State);
            }
            operation()
        };
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(hook) = &self.before {
            hook();
        }
        #[cfg(any(test, feature = "kernel-test"))]
        if self.native.is_none() {
            return if let Some(domain) = &self.model {
                let snapshot = domain.lock().clone();
                self.gate.invoke_with_domain(&snapshot, operation)
            } else {
                self.gate.invoke(operation)
            };
        }
        self.gate.invoke(|| {
            let (device, cap) = self.native.as_ref().ok_or(Error::State)?;
            super::pci_park::invoke(cap, || {
                use narf_bus::pci::{
                    self,
                    cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE},
                };
                let command = pci::read_command(cap, device).map_err(|_| Error::Access)?;
                if command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
                    != (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
                {
                    return Err(Error::Prerequisite);
                }
                operation()
            })
            .map_err(|_| Error::Access)?
        })
    }
    pub(super) fn with_epoch(mut self, epoch: super::station_control::ReceiveEpoch) -> Self {
        self.receive_epoch = Some(epoch);
        self
    }
    pub(super) fn current(&self) -> bool {
        self.receive_epoch
            .as_ref()
            .is_none_or(super::station_control::ReceiveEpoch::current)
    }
}
