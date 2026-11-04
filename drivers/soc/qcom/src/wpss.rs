//! WPSS power sequencing: the proxy votes + AOSS load-state message
//! that bring a TrustZone-PAS WLAN subsystem (WCN6750) up and down.
//!
//! Linux counterparts, in start/stop order:
//!
//! - probe: `qcom_q6v5_adsp.c` `wpss_resource_init` attaches the proxy
//!   power domains `cx` and `mx` (`qcom_rproc_pds_attach`, which lands
//!   in `rpmhpd` votes), and the `xo` clock vote comes from
//!   `clk-rpmh.c` (`bi_tcxo`, `xo.lvl`);
//! - prepare (start): `qcom_q6v5.c` `qcom_q6v5_prepare` sends the AOSS
//!   load-state message with `val: on` for `name: wpss`;
//! - unprepare (stop): `qcom_q6v5_unprepare` sends the same message
//!   with `val: off`. The power-domain votes stay attached across
//!   stop — only the load-state message toggles — and this module
//!   mirrors that exactly.
//!
//! Corner levels for `cx`/`mx` are caller-supplied: they come from the
//! per-SoC DT `qcom,level` tables and are NOT pinned here.
//!
//! This composition does not itself touch the live bring-up: wiring it
//! into `LiveAhb` needs the host DT nodes for the RSC window, the
//! cmd-db reserved-memory region, and the AOSS msgram + mailbox, which
//! no in-tree fixture DT carries yet. That wiring is the follow-up;
//! the drivers and the sequence are complete and fixture-tested here.

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

/// The WPSS power sequence over an [`Rpmh`] vote layer and an open
/// [`Qmp`] channel.
#[derive(Debug)]
pub struct WpssPower<'a, R1: RegIo, R2: RegIo, K: Kick> {
    rpmh: Rpmh<'a, R1>,
    qmp: Qmp<R2, K>,
}

impl<'a, R1: RegIo, R2: RegIo, K: Kick> WpssPower<'a, R1, R2, K> {
    pub fn new(rpmh: Rpmh<'a, R1>, qmp: Qmp<R2, K>) -> Self {
        Self { rpmh, qmp }
    }

    /// Prepare: cast the `cx`/`mx` proxy votes and the `xo` vote, then
    /// send load-state `on` for `wpss`. The vote order follows the
    /// Linux probe order (power domains, then the clock vote implicit
    /// in the interconnect/clock bring-up) with load-state last, as
    /// `qcom_q6v5_prepare` runs after the votes are in place.
    pub async fn prepare<D: Delay + ?Sized>(
        &self,
        delay: &D,
        cx_level: u32,
        mx_level: u32,
    ) -> Result<(), WpssPowerError> {
        self.rpmh
            .vote_rail(delay, "cx", cx_level)
            .await
            .map_err(WpssPowerError::Vote)?;
        self.rpmh
            .vote_rail(delay, "mx", mx_level)
            .await
            .map_err(WpssPowerError::Vote)?;
        self.rpmh
            .vote_xo(delay, true)
            .await
            .map_err(WpssPowerError::Vote)?;
        self.qmp
            .load_state(delay, "wpss", true)
            .await
            .map_err(WpssPowerError::Qmp)?;
        Ok(())
    }

    /// Unprepare: load-state `off` only. The proxy votes stay cast,
    /// exactly as Linux leaves the attached power domains up across
    /// `qcom_q6v5_unprepare`.
    pub async fn unprepare<D: Delay + ?Sized>(&self, delay: &D) -> Result<(), WpssPowerError> {
        self.qmp
            .load_state(delay, "wpss", false)
            .await
            .map_err(WpssPowerError::Qmp)?;
        Ok(())
    }
}
