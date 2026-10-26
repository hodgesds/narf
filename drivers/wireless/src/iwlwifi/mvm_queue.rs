// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained API77 management queue behind an inactive PHY/TX-disabled AP.
//! Linux mvm/sta.c::iwl_mvm_tvqm_enable_txq maps management TID to15 and
//! fw/api/datapath.h supplies SCD_QUEUE_CONFIG v3 ADD/REMOVE. Allocating a
//! queue is not permission to ring its packet doorbell or enable peer TX.
use super::{Owner, Phase};

const STATION: u8 = 0;
const MANAGEMENT_TID: u8 = 15;

#[derive(Clone, Copy)]
pub(super) struct ManagementQueue {
    id: Option<u16>,
}

impl Owner {
    /// Firmware-confirmed prerequisite identity, never a transmit capability.
    pub fn prepared_management_queue(&self) -> Option<u16> {
        if !matches!(
            self.phase,
            Phase::ManagementQueuePrepared
                | Phase::TransmitPowerPrepared
                | Phase::LinkActive
                | Phase::Associated
                | Phase::DataPrepared
        ) || self.hardware.is_failed()
        {
            return None;
        }
        self.management_queue?.id
    }

    /// Bind one owned native queue to the still-disabled station0. The
    /// existing inactive PHY/peer must survive until confirmed queue retirement.
    /// Authenticated platform power/SAR and active station admission stay gated.
    pub async fn prepare_management_queue(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::PeerPrepared
            || self.prepared_ap_peer().is_none()
            || self.management_queue.is_some()
        {
            return Err("MVM owner has no queue-free disabled AP peer");
        }
        if self.hardware.version(5, 0x17) != Some((3, 2)) {
            return Err("unsupported MVM management queue command API");
        }
        // Reserve before the allocator can publish any DMA addresses. Its
        // borrowed future may be cancelled after the firmware fetched them.
        self.management_queue = Some(ManagementQueue { id: None });
        self.phase = Phase::PreparingManagementQueue;
        match self.hardware.allocate_tx(STATION, MANAGEMENT_TID).await {
            Ok(id) => {
                self.management_queue = Some(ManagementQueue { id: Some(id) });
                self.phase = Phase::ManagementQueuePrepared;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }

    /// The queue was never exposed for packet submission. Even so, validate
    /// its exact owner/idle state and await REMOVE before releasing its DMA.
    pub async fn release_management_queue(&mut self) -> Result<(), &'static str> {
        if self.phase != Phase::ManagementQueuePrepared || self.power.prepared.is_some() {
            return Err("MVM management queue still owns transmit-power preparation");
        }
        let id = self
            .prepared_management_queue()
            .ok_or("MVM owner has no prepared management queue")?;
        self.phase = Phase::RemovingManagementQueue;
        match self
            .hardware
            .remove_idle_tx(id, STATION, MANAGEMENT_TID)
            .await
        {
            Ok(()) => {
                self.management_queue = None;
                self.phase = Phase::PeerPrepared;
                Ok(())
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_queue_tests.rs"]
pub(super) mod tests;
