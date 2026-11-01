//! The original API77 Hardware owner enters the common retained AP session.
//! No proxy netdev, copied board table or legacy station grant substitutes.
use super::{Owner, Phase};
use alloc::{boxed::Box, sync::Arc};
use narf_lib::sync::IrqSafeSpinLock;
impl Owner {
    pub(in crate::iwlwifi) fn ap_capable(&self) -> bool {
        self.hardware.ap_legacy_selected()
            && self.scan_power_api()
            && self.power.nvm_permissions.is_some()
    }
    pub(in crate::iwlwifi) fn ap_hardware(&mut self) -> &mut super::super::runtime::Hardware {
        &mut self.hardware
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::iwlwifi) async fn ap_prepare(
        &mut self,
        plan: super::super::ap_wire::Plan,
        settings: narf_wireless::ApStartSettings,
        policy: &super::super::mld_policy::Source,
        proof: Arc<super::super::ap_owner::Owner>,
        request: Arc<super::super::ap_owner::Request>,
        history: Arc<IrqSafeSpinLock<super::super::sc_security::KeyHistory>>,
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
    ) -> Result<super::super::ap_session::Session, &'static str> {
        if self.phase != Phase::Configured
            || self.hardware.is_failed()
            || !self.ap_capable()
            || self.peer.is_some()
            || self.management_queue.is_some()
            || self.power.prepared.is_some()
            || self.channel.current.is_some()
            || plan.channel.band == super::super::native_band::Band::Six
        {
            return Err("MVM AP requires its original idle legacy20 owner");
        }
        let own = self.mac.ok_or("MVM AP original MAC unavailable")?;
        let nvm = self.nvm.as_ref().ok_or("MVM AP original NVM unavailable")?;
        if !nvm.channels.contains(&plan.channel.number) {
            return Err("MVM AP channel absent from actual NVM");
        }
        let chains = nvm.tx_chains;
        let domain = policy.snapshot()?;
        let actual = self.transmit_power_request_for(super::power::Emission::ApLegacy)?;
        if actual.binding != binding {
            return Err("MVM AP supplied qualification binding is stale");
        }
        let power = Box::new(super::ap_power::Plan::new(
            source,
            binding,
            own,
            plan.channel.number,
            &domain,
        )?);
        self.validate_scan_profile()?;
        proof.check()?;
        request.check()?;
        self.phase = Phase::PreparingAp;
        let result = async {
            self.hardware.clear_rf_policy();
            self.hardware.ap_request(Some(request))?;
            self.hardware.install_ap_owner(proof.clone())?;
            self.hardware
                .install_rf_policy(super::super::mld_policy::Authority::Transaction(
                    policy
                        .transaction(&domain)?
                        .with_mvm_ap(power.fence.clone())?,
                ))?;
            // Actual inactive MAC/link/DQA/awake setup, without SCAN_REQ.
            // It creates exactly the idle objects common AP preparation removes.
            self.prepare_scan().await?;
            let (mcc, ibss) = if let Some((version, query)) = self.mcc_request()? {
                let reply = self.hardware.command(1, 0xc8, &query).await?;
                (
                    super::super::mld_regulatory::Mcc::parse_mvm(version, &reply.payload)?,
                    false,
                )
            } else {
                (
                    super::super::mld_regulatory::Mcc {
                        country: *b"00",
                        channels: self
                            .power
                            .nvm_permissions
                            .as_ref()
                            .ok_or("MVM AP nonLAR NVM permissions absent")?
                            .clone()
                            .into(),
                        etsi_5ghz: false,
                        he_allowed: false,
                        eht_allowed: false,
                        widths: super::super::gen3_wire::Widths {
                            forty: false,
                            eighty: false,
                            one_sixty: false,
                            three_twenty: false,
                        },
                    },
                    true,
                )
            };
            let program = super::super::mld_policy::Program::new_mvm_ap(
                &domain,
                mcc,
                plan.channel.number,
                power.fence.clone(),
                ibss,
                self.hardware.rf_policy_validity()?,
            )?;
            self.hardware
                .install_rf_policy(super::super::mld_policy::Authority::Station(
                    policy.bind(program.clone())?,
                ))?;
            super::super::ap_session::Session::prepare_native(
                &mut self.hardware,
                plan,
                settings,
                own,
                chains,
                proof,
                history,
                program,
                Some(power),
            )
            .await
        }
        .await;
        match result {
            Ok(ap) => {
                self.phase = Phase::ApActive;
                Ok(ap)
            }
            Err(error) => {
                self.station_fail();
                Err(error)
            }
        }
    }
    pub(in crate::iwlwifi) async fn ap_stop(&mut self) -> Result<(), &'static str> {
        // This is non-emitting cleanup under the actual original device
        // authority. Dead START/socket/power guards cannot obstruct reset.
        self.hardware.clear_rf_policy();
        self.station_fail();
        self.suspend_transport().await
    }
}
