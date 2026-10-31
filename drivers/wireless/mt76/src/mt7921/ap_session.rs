//! Native AP BSS/beacon command ownership. No host carrier/packet admission
//! is inferred from command completion; the interface publishes separately.
use super::{station::Command, Backend, Error, RadioInfo, Session, Stage, State};
use crate::mt7921::{ap_wire, association::ap::Plan, channel, cmd};
use alloc::{sync::Arc, vec};
use core::future::Future;
use narf_wireless::{
    ap_control::{ApControlAuthority, ApInterfaceIdentity},
    ApConfig,
};

#[derive(Debug)]
pub(super) struct Owner {
    pub info: RadioInfo,
    pub plan: Arc<Plan>,
    pub identity: ApInterfaceIdentity,
    pub peers: super::ap_peer::Peers,
    pub default_group: Option<u8>,
    pub pending_plan: Option<Arc<Plan>>,
    pub events: alloc::collections::VecDeque<ApRxEvent>,
    pub start_settings: Option<narf_wireless::ApStartSettings>,
    pub activated: bool,
    /// Actual request authority survives a dropped borrowed waiter until
    /// host publication or verified cleanup. It grants no new frame owner.
    pub pending: Option<Arc<ApControlAuthority>>,
}

impl<B: Backend> Session<B> {
    pub(super) async fn start_ap_with_settings(
        &mut self,
        authority: Arc<ApControlAuthority>,
        config: ApConfig,
        settings: narf_wireless::ApStartSettings,
    ) -> Result<(), Error> {
        if settings.auth_type.is_some_and(|kind| kind != 0)
            || settings.control_port.ethertype != 0x888e
        {
            return Err(Error::UnsupportedFirmware);
        }
        if config.privacy {
            if settings.wpa_versions.is_some_and(|v| v != 2)
                || settings
                    .pairwise_ciphers
                    .as_ref()
                    .is_some_and(|v| v.as_slice() != [0x000fac04])
                || settings.group_cipher.is_some_and(|v| v != 0x000fac04)
                || settings
                    .akms
                    .as_ref()
                    .is_some_and(|v| v.as_slice() != [0x000fac02])
                || !settings.control_port.enabled
                || !settings.control_port.over_nl80211
            {
                return Err(Error::UnsupportedFirmware);
            }
        } else if settings.wpa_versions.is_some_and(|v| v != 0)
            || settings
                .pairwise_ciphers
                .as_ref()
                .is_some_and(|v| !v.is_empty())
            || settings.group_cipher.is_some_and(|v| v != 0)
            || settings.akms.as_ref().is_some_and(|v| !v.is_empty())
        {
            return Err(Error::UnsupportedFirmware);
        }
        self.start_ap(authority.clone(), config).await?;
        if let Err(error) = self.check_ap_request(&authority) {
            return Err(self.ap_peer_failure(error).await);
        }
        self.ap_owner.as_mut().ok_or(Error::Busy)?.start_settings = Some(settings);
        Ok(())
    }
    pub(super) async fn start_ap(
        &mut self,
        authority: Arc<ApControlAuthority>,
        config: ApConfig,
    ) -> Result<(), Error> {
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        let info = match self.state {
            State::RadioReady(info) | State::ScanReady(info) => info,
            _ => return Err(Error::Busy),
        };
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        let identity = authority.identity().map_err(|_| Error::Authority)?;
        if identity.mac() != info.capabilities.mac {
            return Err(Error::Authority);
        }
        let policy = self.backend.regulatory_domain()?;
        // Reject malformed/unsupported templates before any hardware write.
        let _ = Plan::prepare(info, config.clone(), &policy)?;
        self.renew_receive_epoch()?;
        // AP takeover cannot reuse a station/monitor key/FIFO generation.
        // Cleanup has its existing current device grant and continues even
        // if a requester loses administrative authority while resetting.
        let info = self.recover(info.capabilities.mac).await?;
        authority.current().map_err(|_| Error::Authority)?;
        let policy = self.backend.regulatory_domain()?;
        let plan = Arc::new(Plan::prepare(info, config, &policy)?);
        self.backend.check_tx_permission(plan.permission)?;
        // WFSYS recovery recycled backend capture metadata. Bind the new
        // BSS to a new actual copy-time epoch, after that retirement.
        self.renew_receive_epoch()?;
        self.ap_owner = Some(Owner {
            info,
            plan: plan.clone(),
            identity,
            peers: super::ap_peer::Peers::default(),
            default_group: None,
            pending_plan: None,
            events: alloc::collections::VecDeque::new(),
            start_settings: None,
            activated: false,
            pending: Some(authority.clone()),
        });
        self.stage(Stage::ApStart);
        self.boot_started = Some(self.backend.now_ns());
        let result = self
            .start_ap_inner(info, &plan, &authority)
            .await
            .and_then(|_| self.check_ap_request(&authority));
        self.boot_started = None;
        if let Err(error) = result {
            self.state = State::Failed {
                stage: Stage::ApStart,
                error,
            };
            let _ = self.recover(info.capabilities.mac).await;
            return Err(error);
        }
        self.state = State::AccessPoint {
            info,
            frequency_mhz: plan.config.frequency_mhz,
        };
        Ok(())
    }

    async fn start_ap_inner(
        &mut self,
        info: RadioInfo,
        plan: &Plan,
        authority: &ApControlAuthority,
    ) -> Result<(), Error> {
        let mut dev = [0; 16];
        cmd::encode_uni_dev_info_update(0, 0, true, plan.own, &mut dev).ok_or(Error::Bounds)?;
        self.ap_exchange(authority, Command::Unified { id: 1 }, &dev)
            .await?;
        self.ap_exchange(
            authority,
            Command::Unified { id: 2 },
            &ap_wire::bss(
                plan.own,
                plan.config.beacon_interval as u16,
                plan.config.dtim_period as u8,
                plan.five_ghz,
                false,
                false,
            )?,
        )
        .await?;
        self.ap_exchange(
            authority,
            Command::Extended {
                id: 0x46,
                query: false,
            },
            &[1, 0, 0, 0],
        )
        .await?;
        let mut receive = [0; 76];
        receive[0] = 1;
        receive[1] = 1;
        receive[3] = info.capabilities.phy.spatial_streams.min(2);
        receive[4] = (1 << receive[3]) - 1;
        self.ap_exchange(
            authority,
            Command::Extended {
                id: 0x4e,
                query: false,
            },
            &receive,
        )
        .await?;

        let band = if plan.five_ghz {
            channel::Band::Ghz5
        } else {
            channel::Band::Ghz2
        };
        let mut domain = vec![0; 20];
        domain[..2].copy_from_slice(&plan.permission.country);
        domain[4..7].fill(1);
        domain[7 + usize::from(band.scan_tag())] = 1;
        domain[12..14].copy_from_slice(&u16::from(plan.channel).to_le_bytes());
        self.ap_notify(
            authority,
            Command::Ce {
                id: 0x0f,
                query: false,
            },
            &domain,
        )
        .await?;
        let limits = plan
            .permission
            .rate_limits_for_paths(info.capabilities.phy.spatial_streams)
            .ok_or(Error::Authority)?;
        self.ap_notify(
            authority,
            Command::Ce {
                id: 0x5d,
                query: false,
            },
            &limits,
        )
        .await?;
        self.confirm_command_progress().await?;
        self.check_ap_request(authority)?;
        let mut switch = [0; cmd::CHANNEL_SWITCH_SIZE];
        cmd::encode_channel_switch(
            plan.channel,
            plan.channel,
            0,
            1,
            receive[4],
            band.switch_tag(),
            &mut switch,
        )
        .ok_or(Error::Bounds)?;
        self.ap_exchange(
            authority,
            Command::Extended {
                id: crate::mt7921::regs::MCU_EXT_CMD_CHANNEL_SWITCH,
                query: false,
            },
            &switch,
        )
        .await?;
        self.check_ap_request(authority)?;
        self.backend.pause_ap_timing()?;
        let paused = self.backend.now_ns();
        self.wait(20, |backend| {
            Ok((backend.now_ns().saturating_sub(paused) >= 1_000).then_some(()))
        })
        .await?;
        self.check_ap_request(authority)?;
        let short_slot = u16::from_le_bytes(plan.config.beacon_head[34..36].try_into().unwrap())
            & (1 << 10)
            != 0;
        self.backend.finish_ap_timing(plan.five_ghz, short_slot)?;
        self.check_ap_request(authority)?;
        let bss = ap_wire::bss(
            plan.own,
            plan.config.beacon_interval as u16,
            plan.config.dtim_period as u8,
            plan.five_ghz,
            true,
            false,
        )?;
        self.ap_exchange(authority, Command::Unified { id: 2 }, &bss)
            .await?;
        self.ap_exchange(
            authority,
            Command::Unified { id: 2 },
            &ap_wire::rlm(plan.channel, plan.five_ghz, receive[4]),
        )
        .await?;
        // Both CE commands are no-response native submissions. PSE echo
        // bounds their progress; it is not an invented firmware ACK.
        self.ap_notify(
            authority,
            Command::Ce {
                id: ap_wire::CE_BSS_ABORT,
                query: false,
            },
            &[0; 4],
        )
        .await?;
        self.ap_notify(
            authority,
            Command::Ce {
                id: ap_wire::CE_BSS_CONNECTED,
                query: false,
            },
            &ap_wire::bss_connected(
                plan.config.beacon_interval as u16,
                plan.config.dtim_period as u8,
            ),
        )
        .await?;
        self.confirm_command_progress().await?;
        self.check_ap_request(authority)?;
        self.ap_exchange(authority, Command::Unified { id: 3 }, &ap_wire::group())
            .await?;
        self.ap_exchange(
            authority,
            Command::Unified { id: 2 },
            &ap_wire::beacon(&plan.beacon, plan.tim_offset, None, plan.rate)?,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn stop_ap(&mut self, authority: &ApControlAuthority) -> Result<(), Error> {
        authority.current().map_err(|_| Error::Authority)?;
        self.stop_ap_owned().await
    }

    /// Cleanup also serves admin-DOWN, suspend and hot removal; it uses
    /// the existing device owner, never a newly manufactured admin grant.
    pub(super) async fn stop_ap_owned(&mut self) -> Result<(), Error> {
        let Some(owner) = self.ap_owner.as_ref() else {
            return if matches!(self.state, State::RadioReady(_)) {
                Ok(())
            } else {
                Err(Error::Busy)
            };
        };
        let plan = owner.plan.clone();
        let info = owner.info;
        self.renew_receive_epoch()?;
        self.stage(Stage::ApStop);
        let result = async {
            self.notify(
                Command::Ce {
                    id: ap_wire::CE_BSS_ABORT,
                    query: false,
                },
                &[0; 4],
            )
            .await?;
            self.confirm_command_progress().await?;
            self.exchange(
                Command::Unified { id: 2 },
                &ap_wire::bss(
                    plan.own,
                    plan.config.beacon_interval as u16,
                    plan.config.dtim_period as u8,
                    plan.five_ghz,
                    false,
                    false,
                )?,
            )
            .await?;
            // Stop/reset, rather than a bare command ACK, retires every
            // old AP key/FIFO/packet owner before another role may run.
            self.recover(info.capabilities.mac).await.map(|_| ())
        }
        .await;
        if let Err(error) = result {
            self.state = State::Failed {
                stage: Stage::ApStop,
                error,
            };
            let _ = self.recover(info.capabilities.mac).await;
            return Err(error);
        }
        Ok(())
    }

    fn check_ap_request(&self, authority: &ApControlAuthority) -> Result<(), Error> {
        if self.p2p_rf_busy() {
            return Err(Error::Busy);
        }
        authority.current().map_err(|_| Error::Authority)?;
        let owner = self.ap_owner.as_ref().ok_or(Error::Busy)?;
        owner.identity.current().map_err(|_| Error::Authority)?;
        self.backend.check_tx_permission(owner.plan.permission)
    }

    async fn ap_exchange(
        &mut self,
        authority: &ApControlAuthority,
        command: Command,
        body: &[u8],
    ) -> Result<(), Error> {
        self.check_ap_request(authority)?;
        let result = {
            let mut pending = alloc::boxed::Box::pin(self.exchange(command, body));
            core::future::poll_fn(|cx| {
                if authority.current().is_err() {
                    return core::task::Poll::Ready(Err(Error::Authority));
                }
                pending.as_mut().poll(cx)
            })
            .await
        };
        result?;
        self.check_ap_request(authority)
    }
    async fn ap_notify(
        &mut self,
        authority: &ApControlAuthority,
        command: Command,
        body: &[u8],
    ) -> Result<(), Error> {
        self.check_ap_request(authority)?;
        self.notify(command, body).await?;
        self.check_ap_request(authority)
    }
}

#[path = "ap_beacon.rs"]
mod beacon;
#[path = "ap_control_tx.rs"]
mod control_tx;
#[path = "ap_data.rs"]
mod data;
#[path = "ap_key_session.rs"]
mod keys;
#[path = "ap_management.rs"]
mod management;
#[path = "ap_peer_session.rs"]
mod peer;

/// Native RX copy identity must be rechecked after releasing driver locks
/// and before calling the shared typed exact-source publication API.
#[derive(Debug)]
pub(crate) struct ApRxEvent {
    pub epoch: u64,
    pub event: ApEvent,
}
#[derive(Debug)]
pub(crate) enum ApEvent {
    Management {
        frequency_mhz: u32,
        signal_dbm: Option<i8>,
        frame: alloc::vec::Vec<u8>,
    },
    Control {
        peer: [u8; 6],
        ethertype: u16,
        pdu: alloc::vec::Vec<u8>,
        unencrypted: bool,
    },
}
