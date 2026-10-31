//! Unkeyed management TX on an actual started device and live CNM lease.
//! Power/SKU receipts, packet retirement and peer ACK remain distinct facts.
use super::p2p_management_power::Plan;
use super::station::Command;
use super::*;
use narf_wireless::ap_control::RadioControlAuthority;

#[derive(Clone, Copy, Debug)]
pub(super) struct Emission {
    plan: Plan,
    cookie: u64,
    home: State,
}
impl<B: Backend> Session<B> {
    pub(super) fn check_p2p_management_tx(&self) -> Result<(), Error> {
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let emission = owner.management.tx.ok_or(Error::Authority)?;
        self.check_p2p_request(owner.pending.as_ref().ok_or(Error::Authority)?)?;
        if !self.p2p_roc_current(emission.cookie, emission.plan.frequency_mhz)? {
            return Err(Error::Authority);
        }
        let domain = self.backend.regulatory_domain()?;
        if !emission.plan.current(domain.as_ref()) {
            return Err(Error::Authority);
        }
        if let Some(home) = emission.plan.home {
            self.backend.check_tx_permission(home)?;
            match emission.home {
                State::Associated { .. } if self.station_permission == Some(home) => {}
                State::AccessPoint { .. } => {
                    let ap = self.ap_owner.as_ref().ok_or(Error::Authority)?;
                    ap.identity.current().map_err(|_| Error::Authority)?;
                    if !ap.activated || ap.plan.permission != home {
                        return Err(Error::Authority);
                    }
                }
                _ => return Err(Error::Authority),
            }
        }
        Ok(())
    }
    pub(super) async fn send_p2p_management(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        request: &narf_wireless::MgmtTxRequest,
    ) -> Result<bool, Error> {
        self.check_p2p_request(&authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if !authority.has_reservation() || !self.p2p_ready() {
            return Err(Error::Busy);
        }
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let lease = owner.cnm.lease().ok_or(Error::Busy)?;
        let crate::mt7921::p2p_cnm::Phase::Granted { expires_ns, .. } = lease.phase else {
            return Err(Error::Busy);
        };
        // No host channel label or queued ROC request can grant emission.
        // This first TX profile reuses a real finite lease; it never creates
        // a hidden implicit ROC or extends its firmware-granted deadline.
        let frequency = if request.frequency_mhz == 0 {
            lease.frequency_mhz
        } else {
            request.frequency_mhz
        };
        if !request.offchannel_ok
            || request.duration > crate::mt7921::p2p_wire::MAX_DURATION_MS
            || frequency != lease.frequency_mhz
            || !self.p2p_roc_current(lease.cookie, frequency)?
            || u64::from(request.duration) * 1_000_000
                > expires_ns.saturating_sub(self.backend.now_ns())
        {
            return Err(Error::Bounds);
        }
        let header =
            super::p2p_management_tx_wire::Header::prepare(&request.frame, owner.identity.mac())?;
        let info = owner.info;
        let vif = owner.vif;
        let cookie = lease.cookie;
        let home = self.state;
        let domain = self.backend.regulatory_domain()?;
        let plan = Plan::prepare(
            info,
            domain.as_ref(),
            frequency,
            self.p2p_home_permission()?,
            false,
        )?;
        // All pure request and occupied-channel admission precedes I/O.
        self.quiesce_p2p_packets().await?;
        self.check_p2p_request(&authority)?;
        if !header.multicast {
            // A pending home BA sample cannot be borrowed or reset merely
            // to send management. Refuse before any power/domain command.
            self.backend.arm_p2p_management(vif, header.tid)?;
        }
        let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
        owner.pending = Some(authority);
        owner.management.tx = Some(Emission { plan, cookie, home });
        self.stage(Stage::P2pManagementTx);
        self.boot_started = Some(self.backend.now_ns());
        let result = async {
            self.check_p2p_management_tx()?;
            for row in plan.rows(info)? {
                self.notify(
                    Command::Ce {
                        id: 0x5d,
                        query: false,
                    },
                    &row,
                )
                .await?;
                self.check_p2p_management_tx()?;
            }
            self.confirm_command_progress().await?;
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &plan.domain(info)?,
            )
            .await?;
            self.confirm_command_progress().await?;
            self.check_p2p_management_tx()?;
            self.backend
                .submit_p2p_management(&request.frame, vif, plan.rate)?;
            self.data_pending.push_back(self.backend.now_ns());
            let terminal = self.wait(TIMEOUT_MS, Backend::management_complete).await?;
            self.data_pending.pop_front();
            let ack = if header.multicast {
                if terminal.status != 0 {
                    return Err(Error::Rejected(terminal.status));
                }
                false
            } else {
                self.wait(TIMEOUT_MS, Backend::poll_p2p_management_ack)
                    .await?
            };
            self.check_p2p_management_tx()?;
            // Restore original occupied home rows before its producer can
            // resume after actual finite ROC retirement. A failed restore never
            // returns a saved home state as though the hardware survived.
            for row in plan.home_rows(info)? {
                self.notify(
                    Command::Ce {
                        id: 0x5d,
                        query: false,
                    },
                    &row,
                )
                .await?;
            }
            self.confirm_command_progress().await?;
            let domain = if let Some(permission) = plan.home {
                super::scan::occupied_domain(info, permission, permission.six.is_some())?
            } else {
                super::scan::passive_domain(info)
            };
            self.notify(
                Command::Ce {
                    id: 0x0f,
                    query: false,
                },
                &domain,
            )
            .await?;
            self.confirm_command_progress().await?;
            self.check_p2p_management_tx()?;
            Ok(ack)
        }
        .await;
        self.boot_started = None;
        match result {
            Ok(ack) => {
                let owner = self.p2p_owner.as_mut().ok_or(Error::Busy)?;
                owner.pending = None;
                owner.management.tx = None;
                self.state = home;
                Ok(ack)
            }
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }
}
