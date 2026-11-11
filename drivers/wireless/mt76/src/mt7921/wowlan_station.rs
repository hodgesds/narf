//! Retained associated WoW handoff through native PCI wake/power ownership.
//!
//! Firmware may replace GTK/IGTK while asleep without a host readback. Resume
//! therefore restores D0 and retires the wake route, then uses verified
//! WFSYS reset before any RX publication or fresh RSNA. It never reconstructs
//! host replay/key state from an unspecified firmware wake event.

use super::{station::Command, Backend, Error, Session, Stage, State, WakeAssociation};
use alloc::sync::Arc;
use core::{future::poll_fn, task::Poll};
use narf_power::system_pm::SystemSleepState;
use narf_wireless::WowlanConfig;
use zeroize::Zeroizing;

impl<B: Backend> Session<B> {
    pub(super) async fn suspend_wowlan(
        &mut self,
        config: &WowlanConfig,
        target: SystemSleepState,
    ) -> Result<(), Error> {
        crate::mt7921::wowlan::validate(config)?;
        if let State::WowSuspended { target: armed, .. } = self.state {
            return if armed == target && self.wow_config.as_ref() == Some(config) {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        }
        // WoW offloads only the home link (mt76_connac_mcu_set_suspend_iter
        // would iterate a group vif too); an associated group link refuses.
        if self.group_published() || self.sched_scan_running() {
            return Err(Error::Busy);
        }
        let associated = matches!(self.state, State::Associated { .. }).then_some(self.state);
        let (info, association, setup) = match self.state {
            State::Associated {
                info,
                peer,
                channel,
                aid,
            } => (info, Some(WakeAssociation { peer, channel, aid }), false),
            State::RadioReady(info) if config.net_detect.is_some() => (info, None, true),
            State::ScanReady(info) if config.net_detect.is_some() => (info, None, false),
            _ => return Err(Error::Busy),
        };
        if self.station.peer_lost || associated.is_some() && self.receive_epoch == 0 {
            return Err(Error::Busy);
        }
        self.wow_nlo = config
            .net_detect
            .as_ref()
            .map(|config| {
                super::scan::nlo::Plan::prepare(
                    &self.backend,
                    info,
                    config,
                    self.station.permission,
                )
                .map(Arc::new)
            })
            .transpose()?;
        // Validate the actual home/offload policy before changing an
        // independent control BSS. A live ROC is scheduler ownership, not
        // policy revocation; owned cleanup below retires it before TX work.
        self.check_wow_policy()?;
        // Real endpoint caps, _PRW, strict firmware profile and installed SCI
        // are checked before radio commands. This creates no fake platform
        // grant and does not yet arm PME/GPE or put the endpoint in D3hot.
        self.backend.prepare_wake_route(target)?;
        if self.p2p_owner.is_some() {
            self.stop_p2p_device_owned().await?;
        }
        self.check_wow_tx()?;
        self.wow_config = Some(config.clone());
        self.renew_receive_epoch()?;
        self.stage(Stage::WowSuspend);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            if setup {
                self.scan_setup(info).await?;
                self.check_wow_tx()?;
            }
            // Finish only already-owned user packets/fragments. No probe or
            // invented MSDU is generated to force a firmware receipt.
            self.drain_wow_transmit().await?;
            if let Some(associated) = associated {
                self.service_keys_during_wow(associated).await?;
            }
            if !self.data_pending.is_empty()
                || !self.station.tx_fragments.is_empty()
                || self.data_controls_pending()
            {
                return Err(Error::Busy);
            }
            let rekey = self
                .station
                .security
                .as_ref()
                .map(|security| security.wow_gtk_update())
                .transpose()?;
            self.suspend_wowlan_inner(config, target, rekey).await
        }
        .await;
        self.boot_started = None;
        if let Err(error) = result {
            // No host data authority is restored by a failed or cancelled
            // low-power exchange. Recovery must prove all old firmware/DMA
            // generations retired, including any autonomous offload keys.
            let _ = self.fail_data(error);
            let restored = self.normalize_wake_bus().await;
            if restored.is_ok() {
                let _ = self.recover(info.capabilities.mac).await;
            }
            return Err(error);
        }
        self.state = State::WowSuspended {
            info,
            association,
            target,
        };
        Ok(())
    }

    async fn suspend_wowlan_inner(
        &mut self,
        config: &WowlanConfig,
        target: SystemSleepState,
        rekey: Option<Zeroizing<[u8; 76]>>,
    ) -> Result<(), Error> {
        use crate::mt7921::wowlan;
        if let Some(rekey) = &rekey {
            self.wow_exchange(
                Command::Unified {
                    id: wowlan::UNI_OFFLOAD,
                },
                &rekey[..],
            )
            .await?;
        }
        self.wow_exchange(
            Command::Unified {
                id: wowlan::UNI_OFFLOAD,
            },
            &wowlan::nd_mode(true),
        )
        .await?;
        let gtk = wowlan::gtk_mode(rekey.is_some());
        self.wow_exchange(
            Command::Unified {
                id: wowlan::UNI_OFFLOAD,
            },
            &gtk[..],
        )
        .await?;
        self.wow_exchange(
            Command::Unified {
                id: wowlan::UNI_OFFLOAD,
            },
            &wowlan::arp_mode(true),
        )
        .await?;
        self.wow_exchange(
            Command::Unified {
                id: wowlan::UNI_SUSPEND,
            },
            &wowlan::suspend_mode(true),
        )
        .await?;
        for pattern in &config.patterns {
            self.wow_exchange(
                Command::Unified {
                    id: wowlan::UNI_SUSPEND,
                },
                &wowlan::pattern(pattern, true)?,
            )
            .await?;
        }
        if let (Some(plan), Some(config)) = (self.wow_nlo.clone(), config.net_detect.as_ref()) {
            self.program_wow_nlo(&plan, config).await?;
        }
        self.wow_exchange(
            Command::Unified {
                id: wowlan::UNI_SUSPEND,
            },
            &wowlan::control(config, true)?,
        )
        .await?;
        // Linux mt7921 PCI suspend: associated VIF/key records stay live,
        // then HIF suspend, deep sleep, DMA-idle/off and firmware ownership.
        self.suspend_associated_hif().await?;
        self.check_wow_tx()?;
        self.backend.arm_wake_route(target)?;
        self.check_wow_tx()?;
        // The DMA/FW-own receipts precede actual PMCSR D3hot. The intent
        // remains retained if the posted write or caller future is lost.
        self.backend.enter_wake_d3hot()?;
        self.wait(narf_bus::pci::PM_D3HOT_DELAY_MS + 20, |backend| {
            Ok(backend.wake_power_settled().then_some(()))
        })
        .await?;
        self.backend.verify_wake_d3hot()?;
        self.check_wow_tx()?;
        Ok(())
    }

    /// Every UNI_SUSPEND/UNI_OFFLOAD request opens with
    /// `{ u8 bss_idx; u8 pad[3]; }` = the station vif's `mvif->idx`
    /// (mt76_connac_mcu_set_suspend_mode, _set_wow_ctrl, _set_gtk_rekey,
    /// _set_arp_filter); the station owner's link supplies it.
    async fn wow_exchange(&mut self, command: Command, body: &[u8]) -> Result<(), Error> {
        self.check_wow_tx()?;
        let mut stamped = Zeroizing::new(body.to_vec());
        *stamped.first_mut().ok_or(Error::Bounds)? = self.station.link.bss();
        self.exchange(command, &stamped).await?;
        self.check_wow_tx()
    }

    fn check_wow_tx(&mut self) -> Result<(), Error> {
        if self.station.permission.is_some() {
            self.check_station_tx()?;
        }
        self.check_wow_policy()
    }
    fn check_wow_policy(&self) -> Result<(), Error> {
        if let Some(permission) = self.station.permission {
            self.backend.check_tx_permission(permission)?;
        } else if self.wow_nlo.is_none() {
            return Err(Error::Authority);
        }
        if let Some(nlo) = self.wow_nlo.as_ref() {
            nlo.current(&self.backend)?;
        }
        self.backend.check()
    }

    async fn drain_wow_transmit(&mut self) -> Result<(), Error> {
        poll_fn(|cx| {
            if let Err(error) = self.backend.check().and_then(|_| self.poll_data_tx()) {
                return Poll::Ready(Err(error));
            }
            if self.data_pending.is_empty() {
                return Poll::Ready(if self.station.tx_fragments.is_empty() {
                    Ok(())
                } else {
                    Err(Error::Ring)
                });
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        })
        .await
    }

    pub(super) async fn normalize_wake_bus(&mut self) -> Result<(), Error> {
        // The timestamp lives in the retained backend. A cancelled D3
        // entry must finish its original delay before writing D0; a new
        // future cannot shorten that physical transition.
        self.wait(narf_bus::pci::PM_D3HOT_DELAY_MS + 20, |backend| {
            Ok(backend.wake_power_settled().then_some(()))
        })
        .await?;
        if self.backend.begin_wake_d0()? {
            self.wait(narf_bus::pci::PM_D3HOT_DELAY_MS + 20, |backend| {
                Ok(backend.wake_power_settled().then_some(()))
            })
            .await?;
            self.backend.verify_wake_d0()?;
        }
        self.backend.disarm_wake_route()?;
        Ok(())
    }

    pub(super) async fn resume_wowlan(&mut self, expected_mac: [u8; 6]) -> Result<(), Error> {
        let State::WowSuspended { info, .. } = self.state else {
            return Err(Error::Busy);
        };
        if info.capabilities.mac != expected_mac {
            return Err(Error::InvalidIdentity);
        }
        self.stage(Stage::Resume);
        self.normalize_wake_bus().await?;
        // Hardware GTK rekey has no Linux CONNAC2 readback. Full verified
        // reset is the authority boundary; fresh association is explicit.
        self.recover(expected_mac).await.map(|_| ())
    }
}
