//! WPSS proxy power: the AOSS load-state message and the RPMh proxy
//! votes around a TrustZone-PAS WLAN subsystem (WCN6750) start/stop.
//!
//! Linux `drivers/remoteproc/qcom_q6v5_pas.c` with `sc7280_wpss_resource`
//! (`proxy_pd_names = "cx", "mx"`, `load_state = "wpss"`, `xo` clock):
//!
//! - start (`qcom_pas_start`): `qcom_q6v5_prepare` sends the AOSS
//!   load-state message `val: on` for `name: wpss`; then
//!   `qcom_pas_pds_enable` sets each proxy power domain to
//!   `INT_MAX` (the rail's highest ARC corner, `rpmhpd`) and enables
//!   it; then `clk_prepare_enable(xo)` (`clk-rpmh` `xo.lvl`). A vote
//!   failure unrolls the rails already voted to corner 0 and sends
//!   load-state `off` (`disable_proxy_pds` / `disable_irqs`).
//! - handover (`qcom_pas_handover`, the remote's `handover` SMP2P bit,
//!   or `qcom_pas_stop` when handover never came): `xo` off, then every
//!   proxy domain back to corner 0.
//! - stop (`qcom_pas_stop` → `qcom_q6v5_unprepare`): load-state `off`.
//!
//! Only ACTIVE_ONLY votes are cast ([`crate::rpmh`] scope). A node
//! without `qcom,qmp` skips the load-state message, as `qcom_q6v5_init`
//! leaves `q6v5->qmp` NULL on `-ENODEV`.
//!
//! [`crate::platform::pas_power`] resolves the RSC, cmd-db and AOSS
//! nodes; `ath11k::ahb_live::LiveAhb` drives this around `PasRproc`.

use crate::aoss::{Qmp, QmpError};
use crate::io::{Delay, RegIo};
use crate::ipc::Kick;
use crate::rpmh::{Rpmh, VoteError};

/// WPSS power failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WpssPowerError {
    /// A proxy vote failed.
    Vote(VoteError),
    /// The AOSS load-state message failed.
    Qmp(QmpError),
}

/// `sc7280_wpss_resource.load_state`.
pub const WPSS_LOAD_STATE: &str = "wpss";

/// The PAS proxy-power sequence over an [`Rpmh`] vote layer and an
/// optional open [`Qmp`] channel.
#[derive(Debug)]
pub struct WpssPower<'a, R1: RegIo, R2: RegIo, K: Kick> {
    rpmh: Rpmh<'a, R1>,
    qmp: Option<Qmp<R2, K>>,
    /// `proxy_pd_names` in DT `power-domain-names` order.
    rails: &'a [&'static str],
}

impl<'a, R1: RegIo, R2: RegIo, K: Kick> WpssPower<'a, R1, R2, K> {
    pub fn new(rpmh: Rpmh<'a, R1>, qmp: Option<Qmp<R2, K>>, rails: &'a [&'static str]) -> Self {
        Self { rpmh, qmp, rails }
    }

    /// `q6v5_load_state_toggle` (`qcom_q6v5_prepare` / `_unprepare`).
    pub async fn load_state<D: Delay + ?Sized>(
        &self,
        delay: &D,
        on: bool,
    ) -> Result<(), WpssPowerError> {
        match &self.qmp {
            Some(qmp) => qmp
                .load_state(delay, WPSS_LOAD_STATE, on)
                .await
                .map_err(WpssPowerError::Qmp),
            None => Ok(()),
        }
    }

    /// `qcom_pas_pds_enable` (every rail at its highest corner) then the
    /// `xo` enable. On failure the rails already voted go back to
    /// corner 0 (`unroll_pd_votes` / `disable_proxy_pds`).
    pub async fn proxy_enable<D: Delay + ?Sized>(&self, delay: &D) -> Result<(), WpssPowerError> {
        for (i, rail) in self.rails.iter().enumerate() {
            let r = match self.rpmh.rail_max_corner(rail) {
                Ok(corner) => self.rpmh.vote_rail(delay, rail, corner).await,
                Err(e) => Err(e),
            };
            if let Err(e) = r {
                self.rails_off(delay, &self.rails[..i]).await;
                return Err(WpssPowerError::Vote(e));
            }
        }
        if let Err(e) = self.rpmh.vote_xo(delay, true).await {
            self.rails_off(delay, self.rails).await;
            return Err(WpssPowerError::Vote(e));
        }
        Ok(())
    }

    async fn rails_off<D: Delay + ?Sized>(&self, delay: &D, rails: &[&'static str]) {
        for rail in rails {
            let _ = self.rpmh.vote_rail(delay, rail, 0).await;
        }
    }

    /// `qcom_pas_handover`: `xo` off, then every proxy rail to corner 0
    /// (`qcom_pas_pds_disable`). Linux ignores these results; the first
    /// failure is reported here but every release is still attempted.
    pub async fn proxy_disable<D: Delay + ?Sized>(&self, delay: &D) -> Result<(), WpssPowerError> {
        let mut first = self.rpmh.vote_xo(delay, false).await;
        for rail in self.rails {
            let r = self.rpmh.vote_rail(delay, rail, 0).await;
            if first.is_ok() {
                first = r;
            }
        }
        first.map_err(WpssPowerError::Vote)
    }

    /// The `qcom_pas_start` prefix: load-state `on`, then
    /// [`Self::proxy_enable`]; a vote failure sends load-state `off`.
    pub async fn start<D: Delay + ?Sized>(&self, delay: &D) -> Result<(), WpssPowerError> {
        self.load_state(delay, true).await?;
        if let Err(e) = self.proxy_enable(delay).await {
            let _ = self.load_state(delay, false).await;
            return Err(e);
        }
        Ok(())
    }
}
