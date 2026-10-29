//! TrustZone-authenticated (PAS) Hexagon remoteproc — the SC7280 WPSS that
//! hosts WCN6750 WiFi firmware.
//!
//! Linux `drivers/remoteproc/qcom_q6v5_pas.c` (`adsp_start`/`adsp_stop`)
//! with `sc7280_wpss_resource`: `pas_id` 6, `wpss.mdt`, crash reason SMEM
//! item 626.
//!
//! - **start**: `qcom_q6v5_prepare`; `qcom_mdt_pas_init` (metadata to
//!   `PAS_INIT_IMAGE`, `PAS_MEM_SETUP` for a relocatable image);
//!   `qcom_mdt_load_no_init` into the carve-out; `PAS_AUTH_AND_RESET`;
//!   wait ≤ 5 s for `ready` (on timeout `PAS_SHUTDOWN`); release the
//!   metadata buffer.
//! - **stop**: SMP2P `stop` request, `PAS_SHUTDOWN`, unprepare.
//!
//! Proxy resources Linux votes around start — the RPMh `xo` clock and the
//! `cx`/`mx` power domains via `qcom,qmp` load-state — are the caller's
//! responsibility; NARF has no RPMh/AOSS-QMP driver yet (recorded as a
//! WCN6750 blocker in the wireless ledger).

use crate::io::Delay;
use crate::mdt::{Mdt, SegmentSource};
use crate::q6v5::{Q6v5, START_TIMEOUT_MS, STOP_TIMEOUT_MS};
use crate::rproc::{Carveout, RprocError, RprocState, StopState};
use crate::scm::{Scm, ScmAlloc, SmcConduit};

/// `sc7280_wpss_resource`.
pub const WPSS_PAS_ID: u32 = 6;
pub const WPSS_FIRMWARE: &str = "wpss.mdt";
pub const WPSS_CRASH_REASON: u32 = 626;

/// One PAS remoteproc.
#[derive(Debug)]
pub struct PasRproc {
    pub pas_id: u32,
    /// Leaked at [`Self::new`]: GIC handlers hold `&'static` to it
    /// (`irq::Q6Irqs::bind_gic`) for the remoteproc's lifetime.
    pub q6: &'static Q6v5,
    mem_reloc: u64,
    state: RprocState,
}

impl PasRproc {
    pub fn new(pas_id: u32) -> Self {
        Self {
            pas_id,
            q6: alloc::boxed::Box::leak(alloc::boxed::Box::new(Q6v5::new())),
            mem_reloc: 0,
            state: RprocState::Offline,
        }
    }

    pub fn state(&self) -> RprocState {
        self.state
    }
    pub fn mem_reloc(&self) -> u64 {
        self.mem_reloc
    }

    /// `adsp_start` (with `adsp_load` folded in: Linux keeps the firmware
    /// handle from load to start).
    #[allow(clippy::too_many_arguments)]
    pub async fn start<C: SmcConduit, A: ScmAlloc, D: Delay + ?Sized>(
        &mut self,
        scm: &mut Scm<C>,
        alloc: &mut A,
        fw_name: &str,
        mdt: &[u8],
        src: &(dyn SegmentSource + Sync),
        carveout: &mut Carveout<'_>,
        delay: &D,
        pump: &mut (dyn FnMut(&Q6v5) + Send),
    ) -> Result<(), RprocError> {
        if self.state == RprocState::Running {
            return Err(RprocError::BadState(self.state));
        }
        let m = Mdt::parse(mdt)?;
        self.q6.prepare();
        let meta = match m
            .pas_init(fw_name, src, scm, alloc, self.pas_id, carveout.phys, delay)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                self.q6.unprepare();
                return Err(e.into());
            }
        };
        let r: Result<(), RprocError> = async {
            self.mem_reloc = m.load(fw_name, src, carveout.mem, carveout.phys)?;
            scm.pas_auth_and_reset(self.pas_id, delay).await?;
            if let Err(e) = self.q6.wait_for_start(delay, START_TIMEOUT_MS, pump).await {
                let _ = scm.pas_shutdown(self.pas_id, delay).await;
                return Err(e.into());
            }
            Ok(())
        }
        .await;
        // qcom_scm_pas_metadata_release on every path.
        drop(meta);
        match r {
            Ok(()) => {
                self.state = RprocState::Running;
                Ok(())
            }
            Err(e) => {
                self.q6.unprepare();
                Err(e)
            }
        }
    }

    /// `adsp_stop`. Returns the `PAS_SHUTDOWN` result; a stop-ack timeout
    /// is reported only through the shutdown path, as in Linux.
    pub async fn stop<C: SmcConduit, D: Delay + ?Sized>(
        &mut self,
        scm: &mut Scm<C>,
        stop: &(dyn StopState + Sync),
        delay: &D,
        pump: &mut (dyn FnMut(&Q6v5) + Send),
    ) -> Result<(), RprocError> {
        if self.state == RprocState::Offline {
            return Err(RprocError::BadState(self.state));
        }
        if self.state == RprocState::Running {
            stop.set_stop(true);
            let _ = self.q6.wait_for_stop(delay, STOP_TIMEOUT_MS, pump).await;
            stop.set_stop(false);
        } else {
            self.q6.mark_stopped();
        }
        let r = scm.pas_shutdown(self.pas_id, delay).await;
        self.q6.unprepare();
        self.state = RprocState::Offline;
        r.map_err(RprocError::from)
    }

    /// Record a crash reported by the remote.
    pub fn note_crash(&mut self) {
        if self.q6.crash().is_some() {
            self.state = RprocState::Crashed;
        }
    }
}
