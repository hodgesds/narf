//! The original API77 boot/NVM owner supplies factual MAC/PHY/power
//! preparation to its actual retained control child. No proxy radio or
//! station/AP qualification is substituted for a P2P operation.
use super::{Owner, Phase};
use alloc::sync::Arc;

pub(in crate::iwlwifi) struct Preparation {
    pub plan: super::P2pPowerPlan,
    pub power: Arc<super::P2pPower>,
    pub firmware: super::super::mld_regulatory::Mcc,
    pub ibss: bool,
    pub own: [u8; 6],
    pub channel: super::super::native_band::Channel,
}
impl Owner {
    pub(in crate::iwlwifi) fn p2p_capable(&self) -> bool {
        self.hardware.p2p_gen2_selected()
            && self.scan_power_api()
            && self.power.nvm_permissions.is_some()
    }
    pub(in crate::iwlwifi) fn p2p_hardware(&mut self) -> &mut super::super::runtime::Hardware {
        &mut self.hardware
    }
    pub(in crate::iwlwifi) async fn p2p_start(
        &mut self,
        request: Arc<super::super::p2p_host::Request>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::Configured
            || !self.p2p_capable()
            || self.peer.is_some()
            || self.management_queue.is_some()
            || self.channel.current.is_some()
            || self.power.prepared.is_some()
        {
            return Err("MVM P2P START requires the actual idle configured owner");
        }
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "MVM P2P original image unavailable")?;
        self.hardware.p2p_start_native(&parsed.api, request).await
    }
    pub(in crate::iwlwifi) async fn p2p_prepare(
        &mut self,
        request: Arc<super::super::p2p_host::Request>,
        channel: super::super::native_band::Channel,
        policy: &super::super::mld_policy::Source,
        source: crate::firmware_asset::Asset,
        binding: [u8; 32],
    ) -> Result<Preparation, &'static str> {
        if self.phase != Phase::Configured
            || !self.p2p_capable()
            || channel.band == super::super::native_band::Band::Six
        {
            return Err("MVM P2P native owner/channel unavailable");
        }
        let own = request.own();
        if self.p2p_power_request(own, channel.number)?.binding != binding {
            return Err("MVM P2P supplied tag8 child/channel binding is stale");
        }
        let domain = policy.snapshot()?;
        let plan = super::P2pPowerPlan::new(source, binding, own, channel.number, &domain)?;
        let power = plan.fence.clone();
        self.hardware.p2p_operation(request)?;
        self.hardware.clear_rf_policy();
        self.hardware
            .install_rf_policy(super::super::mld_policy::Authority::Transaction(
                policy.transaction(&domain)?.with_mvm_p2p(power.clone())?,
            ))?;
        self.validate_scan_profile()?;
        // Current original MAC0/DQA/awake configuration is non-emitting;
        // this does not create a grant for the separate actual MAC1.
        self.prepare_scan().await?;
        let (firmware, ibss) = if let Some((version, query)) = self.mcc_request()? {
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
                        .ok_or("MVM P2P original nonLAR NVM permissions absent")?
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
        Ok(Preparation {
            plan,
            power,
            firmware,
            ibss,
            own,
            channel,
        })
    }
}
