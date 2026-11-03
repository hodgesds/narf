// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed original C21/C22 PCI function through MAC-off, D3hot and fresh D0.
use super::{
    functions::{Barrier, ResetClaim},
    operating_reset::{Origin, Retired},
    pci::Rtw88Device,
    power::{self, OffReceipt},
    system_pm_wire,
};
use alloc::{boxed::Box, sync::Arc};
use narf_bus::pci::{PciPowerState, SavedPciConfig};
use narf_power::device_pm::DevicePmError as Error;
pub(super) struct Native {
    owner: Arc<Rtw88Device>,
    barrier: Arc<Barrier>,
}
pub(super) struct Parked {
    claim: ResetClaim,
    retired: Retired,
    off: OffReceipt,
    config: SavedPciConfig,
    name: &'static str,
    rfe6: bool,
    operating: bool,
}
impl Native {
    pub(super) fn new(owner: Arc<Rtw88Device>, barrier: Arc<Barrier>) -> Self {
        Self { owner, barrier }
    }
    fn origin(&self) -> Result<Origin, Error> {
        self.owner.reset_origin.ok_or(Error::NotImplemented)
    }
    fn config<T>(
        &self,
        claim: &ResetClaim,
        operation: impl FnOnce(&Origin) -> Result<T, narf_bus::pci::PciError>,
    ) -> Result<T, Error> {
        let origin = self.origin()?;
        super::pci_park::invoke(&origin.authority, || {
            claim.current().map_err(|_| Error::DriverError)?;
            origin
                .current(&self.owner)
                .map_err(|_| Error::DriverError)?;
            operation(&origin).map_err(|_| Error::DriverError)
        })
        .map_err(|_| Error::DriverError)?
    }
    async fn settle() {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            narf_bus::pci::PM_D3HOT_DELAY_MS * 1_000_000,
        ))
        .await;
    }
    fn state(&self, claim: &ResetClaim, expected: PciPowerState) -> Result<(), Error> {
        if self.config(claim, |origin| {
            narf_bus::pci::power_state(&origin.authority, &origin.device)
        })? != Some(expected)
        {
            return Err(Error::DriverError);
        }
        Ok(())
    }
    async fn abort_fresh(fresh: &Arc<Rtw88Device>) {
        if let Some(interface) = &fresh.interface {
            interface.cancel_control();
        }
        if let Some(removed) = super::functions::begin_remove(fresh.bus_addr) {
            if Arc::ptr_eq(&removed, fresh) && super::pci::remove_owner(fresh).await {
                super::functions::reclaimed(fresh);
            }
        }
    }
}
#[async_trait::async_trait]
impl super::system_pm_worker::Backend for Native {
    type Parked = Parked;
    async fn prepare(&mut self) -> Result<Parked, Error> {
        let owner = self.owner.clone();
        let _provision = owner.provisioning.try_lock().ok_or(Error::Busy)?;
        let origin = self.origin()?;
        origin.current(&owner).map_err(|_| Error::DriverError)?;
        let interface = owner.interface.as_ref().ok_or(Error::NotImplemented)?;
        let lifecycle = owner
            .firmware
            .as_ref()
            .map(|firmware| firmware.lifecycle())
            .or_else(|| owner.sibling.as_ref().map(|sibling| sibling.lifecycle()))
            .ok_or(Error::NotImplemented)?;
        if lifecycle.removed() || interface.withdrawn() {
            return Err(Error::Busy);
        }
        let operating = lifecycle.status().stage == super::firmware_lifecycle::Stage::StationReady;
        // Validate real PM capability/state before any irreversible withdrawal.
        let state = super::pci_park::invoke(&origin.authority, || {
            narf_bus::pci::power_state(&origin.authority, &origin.device)
        })
        .map_err(|_| Error::DriverError)?
        .map_err(|_| Error::NotImplemented)?;
        if state != Some(PciPowerState::D0) {
            return Err(Error::Busy);
        }
        let claim = ResetClaim::acquire_system(&owner, &self.barrier).map_err(|_| Error::Busy)?;
        interface
            .withdraw_for_rebind()
            .map_err(|_| Error::DriverError)?;
        let retired = super::operating_reset::retire(interface, &lifecycle)
            .await
            .map_err(|_| Error::DriverError)?;
        let name = interface.rebound_name().ok_or(Error::DriverError)?;
        let config = self.config(&claim, |origin| {
            narf_bus::pci::save_config(&origin.authority, &origin.device)
        })?;
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        if config.command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE) != MEM_SPACE | INTX_DISABLE {
            return Err(Error::DriverError);
        }
        let rfe6 = owner
            .firmware
            .as_ref()
            .is_some_and(|firmware| firmware.factory().rfe() == 6);
        let off = {
            // SAFETY: exact original function claim and actual original
            // callback/IRQ/DMA retirement, complete exclusively owned BAR.
            let mut io = unsafe {
                power::RecoveryIo::new(&owner.registers, &origin.device, &origin.authority, &claim)
            };
            let off = power::off_with(&mut io, owner.device_id).map_err(|_| Error::DriverError)?;
            if rfe6 {
                system_pm_wire::clkreq_pad(&mut io, true).map_err(|_| Error::DriverError)?;
            }
            off
        };
        let parked = Parked {
            claim,
            retired,
            off,
            config,
            name,
            rfe6,
            operating,
        };
        let result = self.config(&parked.claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D3Hot)
        });
        if result.is_err() {
            // Card-off already completed. Preserve its real receipts through
            // best-effort rollback rather than dropping the original claim.
            let _ = <Self as super::system_pm_worker::Backend>::resume(self, parked).await;
            return Err(Error::DriverError);
        }
        // No config/MMIO accesses during the mandatory D3 settle interval.
        Self::settle().await;
        if self.state(&parked.claim, PciPowerState::D3Hot).is_err() {
            let _ = <Self as super::system_pm_worker::Backend>::resume(self, parked).await;
            return Err(Error::DriverError);
        }
        Ok(parked)
    }
    async fn resume(&mut self, parked: Parked) -> Result<(), Error> {
        let origin = self.origin()?;
        self.config(&parked.claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D0)
        })?;
        Self::settle().await;
        self.state(&parked.claim, PciPowerState::D0)?;
        self.config(&parked.claim, |origin| {
            use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
            narf_bus::pci::clear_command(
                &origin.authority,
                &origin.device,
                BUS_MASTER | MEM_SPACE,
            )?;
            narf_bus::pci::set_command(&origin.authority, &origin.device, INTX_DISABLE)?;
            narf_bus::pci::restore_config(&origin.authority, &origin.device, &parked.config)
        })?;
        let restored = self.config(&parked.claim, |origin| {
            narf_bus::pci::save_config(&origin.authority, &origin.device)
        })?;
        use narf_bus::pci::cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE};
        if restored.bars != parked.config.bars
            || restored.expansion_rom_bar != parked.config.expansion_rom_bar
            || restored.command & (BUS_MASTER | MEM_SPACE | INTX_DISABLE)
                != MEM_SPACE | INTX_DISABLE
        {
            return Err(Error::DriverError);
        }
        if parked.rfe6 {
            // SAFETY: original actual retired function, D0/config restored
            // with BME/IRQ publication closed, full original BAR retained.
            let mut io = unsafe {
                power::RecoveryIo::new(
                    &self.owner.registers,
                    &origin.device,
                    &origin.authority,
                    &parked.claim,
                )
            };
            system_pm_wire::clkreq_pad(&mut io, false).map_err(|_| Error::DriverError)?;
        }
        let Parked {
            claim,
            retired,
            off,
            name,
            operating,
            ..
        } = parked;
        // SAFETY: original claim + actual card-off/D3/D0/config/retirement
        // receipts; no old native producer or mapping remains live.
        let fresh = Arc::new(
            unsafe {
                super::pci::bring_up_resume(
                    &origin.device,
                    &origin.authority,
                    retired,
                    &claim,
                    name,
                    off,
                )
            }
            .map_err(|_| Error::DriverError)?,
        );
        if fresh.mac != self.owner.mac
            || fresh.bus_addr != self.owner.bus_addr
            || fresh.device_id != self.owner.device_id
        {
            return Err(Error::DriverError);
        }
        origin
            .current(&self.owner)
            .map_err(|_| Error::DriverError)?;
        claim.current().map_err(|_| Error::DriverError)?;
        let interface = fresh.interface.as_ref().ok_or(Error::DriverError)?;
        super::interface::publish(interface.clone()).map_err(|_| Error::DriverError)?;
        if claim.publish(fresh.clone()).is_err() {
            interface.withdraw();
            return Err(Error::DriverError);
        }
        if super::pci::provision_owner(&fresh).await.is_err() {
            // A previously unqualified cold shell must survive system PM
            // without inventing missing firmware/board-policy authority.
            // Retain only actual stable parked checkpoints, never a failed
            // or removed native owner; normal explicit provisioning can retry.
            use super::firmware_lifecycle::Stage;
            let lifecycle = fresh
                .firmware
                .as_ref()
                .map(|f| f.lifecycle())
                .or_else(|| fresh.sibling.as_ref().map(|s| s.lifecycle()));
            if !operating
                && !interface.closed()
                && lifecycle.as_ref().is_some_and(|lifecycle| {
                    !lifecycle.removed()
                        && matches!(
                            lifecycle.status().stage,
                            Stage::Detected
                                | Stage::Ready
                                | Stage::MacPrepared
                                | Stage::PhyTablesPrepared
                                | Stage::Calibration8821cPrepared
                                | Stage::Operating8821cPrepared
                                | Stage::Radio8821cPrepared
                                | Stage::Calibrated
                        )
                })
            {
                return Ok(());
            }
            Self::abort_fresh(&fresh).await;
            return Err(Error::DriverError);
        }
        Ok(())
    }
}
