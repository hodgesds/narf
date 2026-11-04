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
    /// A system transition changes PCI D-state. IPS keeps D0 and reserves
    /// only its original function; neither path fabricates DMA retirement.
    barrier: Option<Arc<Barrier>>,
}
pub(super) enum Parked {
    /// MAC-off (`rtw_core_stop` + `rtw_power_off`), retired original owner.
    Cold(Cold),
    /// RTL8822CE Wake-on-WLAN: the original station stays retained and
    /// published, the WoW firmware owns the association, no card-off ran.
    Wow(Wow),
}
pub(super) struct Cold {
    claim: ResetClaim,
    retired: Retired,
    off: OffReceipt,
    config: SavedPciConfig,
    name: &'static str,
    rfe6: bool,
    operating: bool,
    /// cfg80211 keeps `wiphy->wowlan_config` (and the last wake report)
    /// across a full restart; the fresh shell inherits them.
    wowlan: Option<narf_wireless::WowlanConfig>,
    wakeup: Option<super::wow::WakeReport>,
}
pub(super) struct Wow {
    /// System reset claim over the original function; republished to the
    /// same owner on success, handed to the cold path on failure.
    claim: ResetClaim,
    armed: super::wow::Armed,
    config: SavedPciConfig,
}
impl Native {
    pub(super) fn new(owner: Arc<Rtw88Device>, barrier: Arc<Barrier>) -> Self {
        Self {
            owner,
            barrier: Some(barrier),
        }
    }
    pub(super) fn idle(owner: Arc<Rtw88Device>) -> Self {
        Self {
            owner,
            barrier: None,
        }
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
        let claim = if let Some(barrier) = &self.barrier {
            // Validate real PM capability/state before irreversible withdrawal.
            let state = super::pci_park::invoke(&origin.authority, || {
                narf_bus::pci::power_state(&origin.authority, &origin.device)
            })
            .map_err(|_| Error::DriverError)?
            .map_err(|_| Error::NotImplemented)?;
            if state != Some(PciPowerState::D0) {
                return Err(Error::Busy);
            }
            let claim = ResetClaim::acquire_system(&owner, barrier).map_err(|_| Error::Busy)?;
            match self.prepare_wow(interface, claim).await {
                Ok(parked) => return Ok(parked),
                Err(claim) => claim,
            }
        } else {
            // IPS is for the actual unassociated passive station only.
            // Hold its real retained owner across eligibility, reservation
            // and closure: a scan/join cannot slip between check and close.
            interface
                .idle_claim(|| ResetClaim::acquire(&owner).map_err(|_| super::station::Error::Busy))
                .await
                .map_err(|_| Error::Busy)?
        };
        self.prepare_cold(interface, &lifecycle, claim, operating, true)
            .await
            .map(Parked::Cold)
    }
    async fn resume(&mut self, parked: Parked) -> Result<(), Error> {
        match parked {
            Parked::Cold(cold) => self.resume_cold(cold).await,
            Parked::Wow(wow) => {
                let interface = self.owner.interface.clone().ok_or(Error::DriverError)?;
                let owner = self.owner.clone();
                let _provision = owner.provisioning.lock().await;
                match self.resume_wow(&interface, wow).await {
                    Ok(()) => Ok(()),
                    Err(Some(claim)) => {
                        // rtw_ops_resume returning 1: mac80211 restarts the
                        // hardware. Here: the existing cold MAC-off park of
                        // the original station (already D0), then the cold
                        // resume with a fresh shell and fresh association.
                        let lifecycle = self.lifecycle()?;
                        let cold = self
                            .prepare_cold(&interface, &lifecycle, claim, true, false)
                            .await?;
                        self.resume_cold(cold).await
                    }
                    Err(None) => Err(Error::DriverError),
                }
            }
        }
    }
}
impl Native {
    fn lifecycle(
        &self,
    ) -> Result<Arc<super::firmware_lifecycle::Lifecycle<super::pci_firmware::Transport>>, Error>
    {
        self.owner
            .firmware
            .as_ref()
            .map(|firmware| firmware.lifecycle())
            .or_else(|| {
                self.owner
                    .sibling
                    .as_ref()
                    .map(|sibling| sibling.lifecycle())
            })
            .ok_or(Error::NotImplemented)
    }
    /// `rtw_ops_suspend` -> `rtw_wow_suspend`, then the PCI core's
    /// `pci_pm_suspend_noirq`: save config and move the function to D3hot
    /// without card-off (rtw88 `rtw_pci_suspend` powers nothing off).
    /// Returns the claim when WoW is not configured, not applicable or
    /// failed, so the caller takes the existing cold path.
    async fn prepare_wow(
        &mut self,
        interface: &Arc<super::interface::Native>,
        claim: ResetClaim,
    ) -> Result<Parked, ResetClaim> {
        if self.owner.device_id != 0xc822
            || super::wow::support(self.owner.device_id).is_none()
            || interface.wowlan().is_none()
            // rtw_pci_suspend's RFE6 CLKREQ pad step exists only over the
            // retired-function RecoveryIo; such boards keep the cold path.
            || self
                .owner
                .firmware
                .as_ref()
                .is_none_or(|firmware| firmware.factory().rfe() == 6)
        {
            return Err(claim);
        }
        // pci_pm_suspend_noirq -> pci_save_state: BME/MEM stay as the
        // running driver left them; the saved command is restored verbatim.
        let config = match self.config(&claim, |origin| {
            narf_bus::pci::save_config(&origin.authority, &origin.device)
        }) {
            Ok(config) => config,
            Err(_) => return Err(claim),
        };
        let armed = match interface.wow_suspend().await {
            Ok(Some(armed)) => armed,
            Ok(None) | Err(()) => return Err(claim),
        };
        let parked = Wow {
            claim,
            armed,
            config,
        };
        // pci_prepare_to_sleep: D3hot, no card-off. PME/wake-enable is the
        // system-PM owner's and is not claimed here (iwlwifi.md §3.80).
        let result = self.config(&parked.claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D3Hot)
        });
        if result.is_ok() {
            Self::settle().await;
            if self.state(&parked.claim, PciPowerState::D3Hot).is_ok() {
                return Ok(Parked::Wow(parked));
            }
        }
        // Back to D0 and restore the armed station before the cold path.
        let _ = self.config(&parked.claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D0)
        });
        Self::settle().await;
        Err(self.unwind_wow(interface, parked).await)
    }
    /// A suspend-side WoW failure after arming: run `rtw_wow_resume` so the
    /// station owner is coherent again, then hand the claim to the cold path
    /// regardless (the normal image and receipts are re-earned there).
    async fn unwind_wow(
        &mut self,
        interface: &Arc<super::interface::Native>,
        wow: Wow,
    ) -> ResetClaim {
        let Wow { claim, armed, .. } = wow;
        let _ = interface.wow_resume(armed).await;
        claim
    }
    /// PCI core resume (`pci_pm_resume_noirq`: D0 + `pci_restore_state`),
    /// then `rtw_ops_resume` -> `rtw_wow_resume`. `Err(Some(claim))`: the
    /// cold path must run; `Err(None)`: the original function is gone.
    async fn resume_wow(
        &mut self,
        interface: &Arc<super::interface::Native>,
        wow: Wow,
    ) -> Result<(), Option<ResetClaim>> {
        let Wow {
            claim,
            armed,
            config,
        } = wow;
        let origin = self.origin().map_err(|_| None)?;
        let pci = self.config(&claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D0)
        });
        if pci.is_err() {
            drop(armed);
            return Err(Some(claim));
        }
        Self::settle().await;
        let restored = self.state(&claim, PciPowerState::D0).and_then(|()| {
            self.config(&claim, |origin| {
                narf_bus::pci::restore_config(&origin.authority, &origin.device, &config)
            })?;
            self.config(&claim, |origin| {
                narf_bus::pci::save_config(&origin.authority, &origin.device)
            })
        });
        let pci_ok = restored.as_ref().is_ok_and(|restored| {
            restored.bars == config.bars
                && restored.expansion_rom_bar == config.expansion_rom_bar
                && restored.command == config.command
        }) && origin.current(&self.owner).is_ok();
        if !pci_ok {
            drop(armed);
            return Err(Some(claim));
        }
        if interface.wow_resume(armed).await.is_err() {
            return Err(Some(claim));
        }
        if claim.current().is_err() {
            return Err(None);
        }
        // Same original owner: the reservation returns to it unchanged.
        claim.publish(self.owner.clone()).map_err(|_| None)
    }
    /// The existing cold system-suspend park: withdraw the published shell
    /// for rebind, retire the original owner, MAC-off (and the RFE6 pad).
    async fn prepare_cold(
        &mut self,
        interface: &Arc<super::interface::Native>,
        lifecycle: &super::firmware_lifecycle::Lifecycle<super::pci_firmware::Transport>,
        claim: ResetClaim,
        operating: bool,
        d3: bool,
    ) -> Result<Cold, Error> {
        let owner = self.owner.clone();
        let origin = self.origin()?;
        let wowlan = interface.wowlan();
        let wakeup = interface.wakeup();
        interface
            .withdraw_for_rebind()
            .map_err(|_| Error::DriverError)?;
        let retired = super::operating_reset::retire(interface, lifecycle)
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
        let rfe6 = self.barrier.is_some()
            && owner
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
        let parked = Cold {
            claim,
            retired,
            off,
            config,
            name,
            rfe6,
            operating,
            wowlan,
            wakeup,
        };
        if self.barrier.is_none() || !d3 {
            // ps.c::rtw_enter_ips / main.c::rtw_core_stop: actual card-off
            // is enough; IPS does not claim PCI D3 or a system wake source.
            return Ok(parked);
        }
        let result = self.config(&parked.claim, |origin| {
            narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D3Hot)
        });
        if result.is_err() {
            // Card-off already completed. Preserve its real receipts through
            // best-effort rollback rather than dropping the original claim.
            let _ = self.resume_cold(parked).await;
            return Err(Error::DriverError);
        }
        // No config/MMIO accesses during the mandatory D3 settle interval.
        Self::settle().await;
        if self.state(&parked.claim, PciPowerState::D3Hot).is_err() {
            let _ = self.resume_cold(parked).await;
            return Err(Error::DriverError);
        }
        Ok(parked)
    }
    async fn resume_cold(&mut self, parked: Cold) -> Result<(), Error> {
        let origin = self.origin()?;
        if self.barrier.is_some() {
            self.config(&parked.claim, |origin| {
                narf_bus::pci::set_power_state(&origin.authority, &origin.device, PciPowerState::D0)
            })?;
            Self::settle().await;
            self.state(&parked.claim, PciPowerState::D0)?;
        }
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
        let Cold {
            claim,
            retired,
            off,
            name,
            operating,
            wowlan,
            wakeup,
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
        interface.restore_wowlan(wowlan, wakeup);
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
