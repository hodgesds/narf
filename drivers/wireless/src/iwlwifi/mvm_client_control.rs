//! Real API77 on-channel P2P public management using the retained key/queue owner.
use super::{Owner, Phase};
use narf_wireless::reg::RegulatoryDomain;
impl Owner {
    pub(in crate::iwlwifi) async fn client_management(
        &mut self,
        request: &narf_wireless::MgmtTxRequest,
        permit: &super::super::p2p_client_request::Request,
        host: &super::super::mld_policy::Source,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<bool, &'static str> {
        if self.phase != Phase::DataPrepared || !self.data_port_using(&mut policy) {
            return Err("API77 client FRAME lacks actual controlled port");
        }
        let client = self
            .hardware
            .p2p_client_native()
            .ok_or("API77 client FRAME has no physical client")?;
        let mut frame = client.plan.management(request)?;
        let domain = policy()?;
        let snapshot = host.snapshot()?;
        if snapshot.country_code != domain.country_code || snapshot.rules != domain.rules {
            return Err("API77 FRAME original policy providers disagree");
        }
        let (mcc, ibss) = if let Some((version, query)) = self.mcc_request()? {
            let reply = self
                .qualified_link_command(1, 0xc8, &query, &mut policy)
                .await?;
            let mcc = super::super::mld_regulatory::Mcc::parse_mvm(version, &reply)?;
            self.accept_mcc(version, &reply)?;
            (mcc, false)
        } else {
            (
                super::super::mld_regulatory::Mcc {
                    country: *b"00",
                    channels: self
                        .power
                        .nvm_permissions
                        .as_ref()
                        .ok_or("API77 FRAME actual NVM permission absent")?
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
        let power = alloc::sync::Arc::new(self.station_power_fence(&policy()?)?);
        let program = super::super::mld_policy::Program::new_mvm_client_management(
            &domain,
            mcc,
            client.plan.channel.number,
            power,
            ibss,
            client.plan.binding(),
        )?;
        permit.qualify(host.bind(program)?)?;
        let queue = self
            .prepared_management_queue()
            .ok_or("API77 client FRAME actual queue absent")?;
        let status = self
            .associated_station()
            .ok_or("API77 client FRAME association retired")?;
        let chains = self
            .nvm
            .as_ref()
            .ok_or("API77 client FRAME actual NVM absent")?
            .tx_chains;
        let rate = super::super::rates::Rates {
            supported: status.supported_rates,
            basic: status.basic_rates,
        }
        .management_rate(chains & chains.wrapping_neg());
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .ok_or("API77 client FRAME native data owner missing")?;
        frame[22..24].copy_from_slice(&((data.sequence & 4095) << 4).to_le_bytes());
        data.sequence = data.sequence.wrapping_add(1) & 4095;
        self.phase = Phase::TransmittingData;
        match self
            .qualified_management_transmit(queue, &frame, rate, &mut policy)
            .await
        {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(true)
            }
            Err(super::super::runtime::TX_FAILED) => {
                self.phase = Phase::DataPrepared;
                Ok(false)
            }
            Err(reason) => self.data_failed(reason),
        }
    }
}
