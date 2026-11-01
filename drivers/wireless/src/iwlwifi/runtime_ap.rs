//! Actual TXPATH_FLUSHv2 response ownership for AP peer retirement. The
//! firmware response proves a native prefix; an empty ACK releases nothing.
use super::*;
impl Hardware {
    pub(in crate::iwlwifi) fn ap_legacy_selected(&self) -> bool {
        self.ap_gen2.is_some()
    }
    /// Called by the actual API77 boot owner after correlated NVM. An
    /// unsupported AP ABI leaves ordinary station boot available; this is
    /// only a consumer selection, never AP emission/power admission.
    pub(in crate::iwlwifi) fn retain_gen2_ap_adapter(
        &mut self,
        api: &super::super::firmware_api::FirmwareApi<'_>,
        nvm: &super::super::station_api::Nvm,
    ) {
        self.ap_gen2 = super::super::ap_gen2_wire::Adapter::read(api, nvm).ok();
    }
    pub(in crate::iwlwifi) fn ap_software_bip(&self) -> bool {
        self.ap_gen2
            .as_ref()
            .is_some_and(|adapter| adapter.software_bip)
    }
    pub(in crate::iwlwifi) fn ap_mpdu<'a>(
        &self,
        bytes: &'a [u8],
    ) -> Option<super::super::scan_api::Mpdu<'a>> {
        if self.ap_gen2.is_some() {
            super::super::scan_api::mpdu_gen2(bytes)
        } else {
            super::super::scan_api::mpdu(bytes)
        }
    }
    pub(in crate::iwlwifi) async fn ap_remove_peer(&mut self, id: u8) -> Result<(), &'static str> {
        if let Some(adapter) = &self.ap_gen2 {
            let body = adapter.remove(id)?;
            if !self.command(1, 0x19, &body).await?.payload.is_empty() {
                return Err("API77 AP REMOVE_STA native receipt unexpected");
            }
            self.ap_gen2.as_mut().unwrap().removed(id);
            Ok(())
        } else {
            super::super::ap_session::command(self, 3, 0xc, &u32::from(id).to_le_bytes()).await
        }
    }
    pub(in crate::iwlwifi) fn ap_request(
        &mut self,
        authority: Option<alloc::sync::Arc<super::super::ap_owner::Request>>,
    ) -> Result<(), &'static str> {
        if let Some(guard) = &authority {
            guard.check()?;
        }
        self.ap_request = authority;
        Ok(())
    }
    pub(in crate::iwlwifi) fn ap_command_cursor(&self) -> u16 {
        self.resources.commands.write
    }
    pub(in crate::iwlwifi) async fn ap_flush_station(
        &mut self,
        station: u8,
    ) -> Result<(), &'static str> {
        if station >= 32 || self.command_version(1, 0x1e) != Some(2) {
            return Err("AP native station flush ABI absent");
        }
        let snapshots: Vec<_> = self
            .resources
            .data
            .iter()
            .filter_map(|q| q.ap_snapshot(station))
            .collect();
        let mut command = [0; 8];
        boot_context::put32(&mut command, 0, u32::from(station));
        command[4..6].copy_from_slice(&0xffffu16.to_le_bytes());
        let receipt = self.command(1, 0x1e, &command).await?;
        let body = receipt.payload;
        if body.len() != 132
            || u16::from_le_bytes(body[..2].try_into().unwrap()) != u16::from(station)
        {
            return Err("AP flush lacks native STA/prefix extent");
        }
        let count = usize::from(u16::from_le_bytes(body[2..4].try_into().unwrap()));
        if count > 16 {
            return Err("AP flush queue count exceeds native response");
        }
        let mut retire = Vec::new();
        for record in body[4..4 + count * 8].chunks_exact(8) {
            let tid = u16::from_le_bytes(record[..2].try_into().unwrap());
            let queue = u16::from_le_bytes(record[2..4].try_into().unwrap());
            let before = u16::from_le_bytes(record[4..6].try_into().unwrap());
            let after = u16::from_le_bytes(record[6..8].try_into().unwrap());
            let (_, owned_tid, read, write) = snapshots
                .iter()
                .copied()
                .find(|x| x.0 == queue)
                .ok_or("AP flush named an unowned native queue")?;
            if tid != u16::from(owned_tid) || retire.iter().any(|&(q, _)| q == queue) {
                return Err("AP flush TID/duplicate queue differs from owner");
            }
            let actual = self
                .resources
                .data
                .iter()
                .find(|q| q.id() == Some(queue))
                .ok_or("AP flush actual queue retired early")?;
            if !actual.belongs_to(station, owned_tid) {
                return Err("AP flush queue changed native STA/TID");
            }
            actual.validate_ap_flush(read, write, before, after)?;
            retire.push((queue, after));
        }
        for &(queue, _, _, write) in &snapshots {
            let actual = self
                .resources
                .data
                .iter()
                .find(|q| q.id() == Some(queue))
                .ok_or("AP flush owner disappeared")?;
            if !retire.iter().any(|&(q, _)| q == queue)
                && actual
                    .ap_snapshot(station)
                    .is_none_or(|(_, _, read, _)| read != write)
            {
                return Err("AP flush omitted outstanding native DMA queue");
            }
        }
        // All identities/extents/pointers validate before any DMA reclaim.
        self.source_fence()?.invoke(|| Ok(()))?;
        for (queue, after) in retire {
            self.resources
                .data
                .iter_mut()
                .find(|q| q.id() == Some(queue))
                .unwrap()
                .reclaim(after)?;
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub(in crate::iwlwifi) fn enqueue_transmit_ap(
        &mut self,
        id: u16,
        frame: &[u8],
        header: usize,
        rate: Option<u32>,
        encrypt: bool,
        assist: u32,
    ) -> Result<(), &'static str> {
        if self.is_failed() {
            return Err("AP native transport failed");
        }
        let source = self.source_fence()?;
        self.check_six_tx_publication()?;
        let queue = self
            .resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("AP native TX queue absent")?;
        source.invoke(|| {
            queue.send_ap_assisted(&mut self.mmio, frame, header, rate, encrypt, assist)
        })?;
        self.count_protected(frame);
        Ok(())
    }
}
