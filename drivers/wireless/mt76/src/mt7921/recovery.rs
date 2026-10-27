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
        if self.state == State::Prepared {
            return Err(Error::Busy);
        }
        self.boot_started = None;
        self.rx_ba.fence();
        self.tx_ba.fence();
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
        self.rx_ba.reset_after_quiescence();
        self.tx_ba.reset_after_quiescence();
        self.tid0_used = false;
        self.security = None;
        self.wmm = None;
        self.wmm_pending = None;
        self.station_permission = None;
        self.ht20_rx = None;
        self.ht20_profile = None;
        self.vht_profile = None;
        self.ap_phy = None;
        self.control_pending.clear();
        self.received_msdu.clear();
        self.station_bss = None;
        self.data_pending.clear();
        self.peer_lost = false;
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
