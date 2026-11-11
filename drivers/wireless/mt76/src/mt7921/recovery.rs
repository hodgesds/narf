//! Verified WFSYS reset followed by a fresh firmware/radio initialization.
//! Linux reference: mt792x_dma.c::mt792x_wfsys_reset_default.
use super::{Backend, Error, RadioInfo, Session, Stage, State};

impl<B: Backend> Session<B> {
    pub(super) async fn recover(&mut self, expected_mac: [u8; 6]) -> Result<RadioInfo, Error> {
        if expected_mac == [0; 6] || expected_mac[0] & 1 != 0 {
            return Err(Error::Bounds);
        }
        self.recover_identity(Some(expected_mac)).await
    }

    // Only the unregistered boot owner can recover without an earlier MAC.
    // initialize_radio still requires a valid firmware-reported identity.
    pub(super) async fn recover_unregistered(&mut self) -> Result<RadioInfo, Error> {
        self.recover_identity(None).await
    }

    async fn recover_identity(
        &mut self,
        expected_mac: Option<[u8; 6]>,
    ) -> Result<RadioInfo, Error> {
        // A GO operation never resets in place: the WFSYS reset would
        // retire the live home association. The GO role stays `Failed`
        // until the home owner's verified recovery retires both.
        if self.state == State::Prepared || self.go_role() {
            return Err(Error::Busy);
        }
        // Keep the original request's serialization lease through the
        // entire cleanup, including firmware reinitialization after the
        // old autonomous AP owner is retired and removed below.
        let _ap_request = self
            .ap_owner
            .as_ref()
            .and_then(|owner| owner.pending.clone());
        let _p2p_request = self
            .p2p_owner
            .as_ref()
            .and_then(|owner| owner.pending.clone());
        self.boot_started = None;
        self.station.rx_ba.fence();
        self.station.tx_ba.fence();
        self.stage(Stage::RecoveryPark);
        let result = self.recover_inner(expected_mac).await;
        if let Err(error) = result {
            let stage = match self.state {
                State::Running(stage) | State::Failed { stage, .. } => stage,
                _ => Stage::RecoveryReady,
            };
            self.state = State::Failed { stage, error };
        }
        result
    }

    async fn recover_inner(&mut self, expected_mac: Option<[u8; 6]>) -> Result<RadioInfo, Error> {
        self.normalize_wake_bus().await?;
        self.backend.check()?;
        self.backend.park_bus_master()?;
        let mut owned = false;
        for _ in 0..10 {
            self.backend.request_link_own()?;
            let requested_at = self.backend.now_ns();
            self.wait(20, |backend| {
                Ok((backend.now_ns().saturating_sub(requested_at) >= 3_000_000).then_some(()))
            })
            .await?;
            match self
                .wait(50, |backend| {
                    backend.link_owned().map(|owned| owned.then_some(()))
                })
                .await
            {
                Ok(()) => {
                    owned = true;
                    break;
                }
                Err(Error::Timeout) => {}
                Err(error) => return Err(error),
            }
        }
        if !owned {
            return Err(Error::Timeout);
        }
        self.backend.quiesce()?;
        self.stage(Stage::RecoveryReset);
        self.backend.assert_reset()?;
        let held_since = self.backend.now_ns();
        self.wait(100, |backend| {
            Ok((backend.now_ns().saturating_sub(held_since) >= 50_000_000).then_some(()))
        })
        .await?;
        self.backend.release_reset()?;
        self.stage(Stage::RecoveryReady);
        self.wait(500, |backend| {
            backend.reset_done().map(|ready| ready.then_some(()))
        })
        .await?;
        // The reset may change DMA control state. Repeat the stop and prove
        // idle before touching descriptors, payloads, tokens or queued replies.
        self.backend.quiesce()?;
        self.wait(100, |backend| backend.idle().map(|idle| idle.then_some(())))
            .await?;
        self.backend.release()?;
        self.stage(Stage::RecoveryRearm);
        self.backend.recycle()?;
        self.cancel_transmit_ba_restart();
        self.station.rx_ba.reset_after_quiescence();
        self.station.tx_ba.reset_after_quiescence();
        self.scan_packets.clear();
        self.scanning = false;
        self.station.used_tids = 0;
        self.station.security = None;
        // Only verified MAC/FW reset plus DMA retirement releases AP owners.
        self.ap_owner = None;
        self.p2p_owner = None;
        self.p2p_next = 1;
        // The verified reset retired every vif's native BSS/WTBL state.
        self.retire_group_link();
        self.retire_go();
        self.ap_keys.clear_active();
        self.wow_config = None;
        self.wow_nlo = None;
        self.sched = None;
        self.station.wmm = None;
        self.station.wmm_pending = None;
        self.station.permission = None;
        self.station.ht20_rx = None;
        self.station.ht20_profile = None;
        self.station.vht_profile = None;
        self.station.he_profile = None;
        self.station.ap_phy = None;
        self.station.control_pending.clear();
        self.station.tx_fragments.clear();
        self.station.received_msdu.clear();
        self.station.demuxed.clear();
        self.station.tx_credit.clear();
        self.station.bss = None;
        self.station.network = crate::mt7921::p2p_wire::Network::Infrastructure;
        self.data_pending.clear();
        self.station.peer_lost = false;
        self.events.clear();
        self.transferred = 0;
        self.seq = 0;
        self.scan_seq = 0;
        self.state = State::Prepared;
        self.run().await?;
        let info = self.initialize_radio().await?;
        if expected_mac.is_some_and(|mac| info.capabilities.mac != mac) {
            return Err(Error::InvalidIdentity);
        }
        Ok(info)
    }
}
