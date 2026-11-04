//! Real physical client MAC7 and source-owned CTWindow update receipts.
use super::*;
use alloc::sync::Arc;
impl Hardware {
    pub(in crate::iwlwifi) fn client_receive_host(
        &mut self,
        host: alloc::sync::Arc<super::super::p2p_client_rx::Host>,
        receiver: super::super::p2p_client_rx::Receiver,
    ) -> Result<(), &'static str> {
        self.source_fence()?.invoke(|| Ok(()))?;
        // Retire the actual already-completed fallback prefix before the new
        // metadata subscription can observe its first copied notification.
        for _ in 0..=RX_DEPTH / 64 {
            if !self.has_pending_rx() {
                break;
            }
            self.poll()?;
        }
        if self.has_pending_rx() {
            return Err("CLIENT registration physical receive prefix kept moving");
        }
        self.client_rx = Some(host);
        self.client_receiver = Some(receiver);
        Ok(())
    }
    pub(in crate::iwlwifi) fn client_refresh_filter(&self) {
        if let Some(native) = &self.p2p_client {
            native.request_probes(self.client_rx.as_ref().is_some_and(|h| h.wants_probes()));
        }
    }
    pub(in crate::iwlwifi) fn client_filter_pending(&self) -> bool {
        self.p2p_client
            .as_ref()
            .is_some_and(|native| native.pending())
    }
    pub(in crate::iwlwifi) fn client_receive_power(
        &mut self,
        power: super::super::p2p_client_rx::MvmPower,
    ) {
        self.client_rx_mvm = Some(alloc::sync::Arc::new(power));
    }
    pub(in crate::iwlwifi) fn take_client_events(
        &mut self,
    ) -> alloc::vec::Vec<super::super::p2p_client_rx::Publication> {
        core::mem::take(&mut self.client_copies)
    }

    pub(in crate::iwlwifi) fn client_request(
        &mut self,
        request: Option<Arc<super::super::p2p_client_request::Request>>,
    ) -> Result<(), &'static str> {
        if let Some(request) = &request {
            request.check()?;
        }
        self.client_request = request;
        Ok(())
    }

    pub(in crate::iwlwifi) fn p2p_client_native(
        &self,
    ) -> Option<Arc<super::super::p2p_client::Native>> {
        self.p2p_client.clone()
    }

    pub(in crate::iwlwifi) fn install_p2p_client(
        &mut self,
        plan: super::super::p2p_client::Plan,
        role: narf_net::native_emission::Lifetime,
    ) -> Result<Arc<super::super::p2p_client::Native>, &'static str> {
        self.source_fence()?.invoke(|| Ok(()))?;
        if self.p2p_client.is_some()
            || self.ap_owner.is_some()
            || self.p2p_started()
            || !matches!(self.command_version(3, 8), Some(1..=3))
        {
            return Err("P2P client original MAC consumer busy/unsupported");
        }
        let native = super::super::p2p_client::Native::new(
            plan,
            role,
            self.format == rx_rfh::CompletionFormat::Qu,
        )?;
        native.request_probes(self.client_rx.as_ref().is_some_and(|h| h.wants_probes()));
        self.p2p_client = Some(native.clone());
        Ok(native)
    }
    pub(in crate::iwlwifi) async fn prepare_p2p_client(&mut self) -> Result<(), &'static str> {
        let native = self
            .p2p_client
            .clone()
            .ok_or("P2P client original role absent")?;
        native.current()?;
        let own = native.plan.own;
        let channel = native.plan.channel;
        self.command(
            3,
            9,
            &super::super::station_api::link(3, own, false, channel.number, 0, 1),
        )
        .await?;
        self.command(3, 8, &super::super::station_api::mac(3, own, None))
            .await?;
        // All original RFH copies precede this real marker. Native beacons
        // are attributed only after retirement, before publishing new MAC7.
        self.synchronize_receive_epoch().await?;
        native.begin_copy()?;
        let window = native.desired();
        self.command(3, 8, &native.mac(1, None, window)?).await?;
        native.commit_window(window, false)?;
        self.command(
            3,
            9,
            &super::super::station_api::link(1, own, false, channel.number, 0, 1),
        )
        .await?;
        native.mark_prepared()
    }
    /// Caller has terminal peer/queue/PHY retirement. Detach the dead
    /// emitting role first; non-emitting physical cleanup still invokes the
    /// original device/firmware authority, never a replacement Admin source.
    pub(in crate::iwlwifi) async fn restore_p2p_client_default(
        &mut self,
    ) -> Result<(), &'static str> {
        let Some(client) = self.p2p_client.take() else {
            return Ok(());
        };
        client.retire();
        let own = client.plan.own;
        let channel = client.plan.channel.number;
        let mut removed = super::super::station_api::mac(3, own, None);
        boot_context::put32(&mut removed, 8, 7);
        let mut restored = super::super::station_api::mac(1, own, None);
        if self.format == rx_rfh::CompletionFormat::Qu {
            boot_context::put32(&mut restored, 20, 12);
        }
        for (group, command, body) in [
            (
                3,
                9,
                super::super::station_api::link(3, own, false, channel, 0, 1).to_vec(),
            ),
            (3, 8, removed.to_vec()),
            (3, 8, restored.to_vec()),
            (
                3,
                9,
                super::super::station_api::link(1, own, false, channel, 0, 1).to_vec(),
            ),
        ] {
            if !self
                .command(group, command, &body)
                .await?
                .payload
                .is_empty()
            {
                return Err("P2P client inactive default restore lacks native receipt");
            }
        }
        Ok(())
    }
    pub(in crate::iwlwifi) fn check_client_tx_publication(&mut self) -> Result<(), &'static str> {
        self.client_refresh_filter();
        let Some(native) = self.p2p_client.clone() else {
            return Ok(());
        };
        native.current()?;
        for _ in 0..=RX_DEPTH / 64 {
            if !self.has_pending_rx() {
                break;
            }
            self.poll()?;
            native.current()?;
        }
        if self.has_pending_rx() {
            return Err("P2P client physical receive prefix kept moving");
        }
        native.transmission()?;
        if let Some(request) = &self.client_request {
            request.transmission()?;
        }
        Ok(())
    }
    pub(in crate::iwlwifi) async fn service_p2p_client(&mut self) -> Result<(), &'static str> {
        let Some(native) = self.p2p_client.clone() else {
            return Ok(());
        };
        for _ in 0..4 {
            match self.check_client_tx_publication() {
                Ok(()) => return Ok(()),
                Err(super::super::p2p_client::UPDATE_REQUIRED) => {}
                Err(e) => return Err(e),
            }
            let window = native.desired();
            let body = native.update_mac()?;
            let probe = u32::from_le_bytes(body[20..24].try_into().unwrap()) & 32 != 0;
            let receipt = self.command(3, 8, &body).await?;
            if !receipt.payload.is_empty() {
                return Err("P2P client CTWindow command lacks native receipt");
            }
            self.source_fence()?
                .invoke(|| native.commit_window(window, probe))?;
        }
        Err("P2P client NoA kept changing across native receipts")
    }
}
