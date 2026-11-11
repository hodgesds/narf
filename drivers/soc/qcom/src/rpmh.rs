//! RPMh resource state coordinator (RSC) + the proxy-vote layer on top.
//!
//! Linux counterparts: `drivers/soc/qcom/rpmh-rsc.c` (TCS programming),
//! `drivers/soc/qcom/rpmh.c` (`rpmh_write`, active-only state),
//! `drivers/pmdomain/qcom/rpmhpd.c` (rail votes via `cmd_db_read_addr`),
//! `drivers/clk/qcom/clk-rpmh.c` (the `xo` clock vote).
//!
//! A vote is one TCS command: `(RSC address from cmd-db, level)` written
//! as an ACTIVE_ONLY request and waited on. Linux sends active/wake/
//! sleep votes for resources with peers; this scope sends ACTIVE_ONLY
//! only — the vote that takes effect immediately — which is what a
//! remoteproc proxy vote needs before the remote boots. Wake/sleep
//! peer aggregation is rpmhpd policy, not part of this module.
//!
//! TCS programming, from `rpmh-rsc.c` (`__tcs_buffer_write`,
//! `__tcs_set_trigger`, `tcs_tx_done`):
//!
//! ```text
//! per slot i:  CMD_MSGID = 8 | WRITE | (RESP_REQ if waited)
//!              CMD_ADDR  = resource address
//!              CMD_DATA  = vote value
//! CMD_ENABLE |= used-slot bits          (read-modify-write)
//! CONTROL: clear TRIGGER, clear ENABLE, set ENABLE, set ENABLE|TRIGGER
//! completion: IRQ_STATUS bit for the TCS (Linux gets it via IRQ;
//!             this module polls it through io::poll_reg, which sleeps
//!             through io::Delay instead of spinning)
//! teardown (mirrors tcs_tx_done): clear TRIGGER, clear ENABLE,
//!             CMD_ENABLE = 0, IRQ_CLEAR = TCS bit
//! ```
//!
//! Register tables: `rpmh_rsc_reg_offset_ver_2_7` (command stride 20)
//! and `rpmh_rsc_reg_offset_ver_3_0` (stride 24), selected by the major
//! version in the ID register at DRV offset 0 (major = bits 16..23,
//! minor = bits 8..15; major >= 3 selects the 3.0 table). The TCS
//! stride is 672 in both tables; the TCS region base itself comes
//! from DT (`qcom,tcs-offset`) and is a constructor argument — it is
//! NOT guessed here. Each TCS holds up to 16 commands.
//!
//! Single-TCS assumption: this module programs the first ACTIVE TCS
//! (TCS 0 unless [`Rsc::with_active_tcs`] names the DT-derived index).
//! Linux picks a free TCS from the ACTIVE group per request; the
//! proxy-vote path is the only RSC user in this scope, so the first
//! ACTIVE TCS is always free. A second RSC user must add allocation
//! first.
//!
//! Nothing here has run on Qualcomm silicon. All constants below are
//! transcribed from the Linux sources named above.

use crate::cmd_db::CmdDb;
use crate::io::{poll_reg, Delay, RegIo};

/// DRV ID register offset (`RSC_DRV_ID`).
const DRV_ID: u32 = 0;
/// TCS block stride (`RSC_DRV_TCS_OFFSET`), both register tables.
const TCS_STRIDE: u32 = 672;
/// Commands per TCS (reserved address space; `ncpt` may be smaller).
const MAX_CMDS_PER_TCS: usize = 16;

/// `CMD_MSGID_LEN`.
const MSGID_LEN: u32 = 8;
/// `CMD_MSGID_RESP_REQ`.
const MSGID_RESP_REQ: u32 = 1 << 8;
/// `CMD_MSGID_WRITE`.
const MSGID_WRITE: u32 = 1 << 16;
/// `TCS_AMC_MODE_ENABLE`.
const AMC_ENABLE: u32 = 1 << 16;
/// `TCS_AMC_MODE_TRIGGER`.
const AMC_TRIGGER: u32 = 1 << 24;

/// Poll sleep between completion reads (NARF policy; Linux waits on
/// the TCS IRQ instead).
const POLL_SLEEP_US: u32 = 100;
/// Poll timeout for a waited TCS transfer (NARF policy; mirrors the
/// 1 s QMP wait, not a Linux RSC literal).
const POLL_TIMEOUT_US: u32 = 1_000_000;

/// One register table (`rpmh_rsc_reg_offset_ver_*`).
#[derive(Copy, Clone, Debug)]
struct RscRegs {
    cmd_stride: u32,
    irq_enable: u32,
    irq_status: u32,
    irq_clear: u32,
    cmd_wait_for_cmpl: u32,
    control: u32,
    status: u32,
    cmd_enable: u32,
    cmd_msgid: u32,
    cmd_addr: u32,
    cmd_data: u32,
    cmd_status: u32,
    cmd_resp_data: u32,
}

const REGS_2_7: RscRegs = RscRegs {
    cmd_stride: 20,
    irq_enable: 0x00,
    irq_status: 0x04,
    irq_clear: 0x08,
    cmd_wait_for_cmpl: 0x10,
    control: 0x14,
    status: 0x18,
    cmd_enable: 0x1c,
    cmd_msgid: 0x30,
    cmd_addr: 0x34,
    cmd_data: 0x38,
    cmd_status: 0x3c,
    cmd_resp_data: 0x40,
};

const REGS_3_0: RscRegs = RscRegs {
    cmd_stride: 24,
    irq_enable: 0x00,
    irq_status: 0x04,
    irq_clear: 0x08,
    cmd_wait_for_cmpl: 0x20,
    control: 0x24,
    status: 0x28,
    cmd_enable: 0x2c,
    cmd_msgid: 0x34,
    cmd_addr: 0x38,
    cmd_data: 0x3c,
    cmd_status: 0x40,
    cmd_resp_data: 0x44,
};

/// RSC failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RscError {
    /// No commands in the request.
    Empty,
    /// More than [`MAX_CMDS_PER_TCS`] commands.
    TooManyCmds,
    /// The TCS completion bit never appeared within the poll budget.
    Timeout,
}

/// An RPMh RSC: one DRV's register window plus its TCS region base.
#[derive(Debug)]
pub struct Rsc<R: RegIo> {
    regs: R,
    table: &'static RscRegs,
    /// DT `qcom,tcs-offset`: base of the TCS region within the DRV.
    tcs_base: u32,
    /// Index of the first ACTIVE TCS (`drv->tcs[ACTIVE_TCS].offset`).
    active_tcs: u32,
}

impl<R: RegIo> Rsc<R> {
    /// Probe: read the DRV ID register and select the register table
    /// (major >= 3 selects the 3.0 table, else 2.7), as `rpmh-rsc.c`
    /// probe does. `tcs_base` is the DT `qcom,tcs-offset` value.
    pub fn probe(regs: R, tcs_base: u32) -> Self {
        let id = regs.read32(DRV_ID);
        let major = (id >> 16) & 0xff;
        let table = if major >= 3 { &REGS_3_0 } else { &REGS_2_7 };
        Self {
            regs,
            table,
            tcs_base,
            active_tcs: 0,
        }
    }

    /// Select the first ACTIVE TCS from DT `qcom,tcs-config`
    /// ([`crate::platform::RscDt::active_tcs`]), as
    /// `rpmh_probe_tcs_config` numbers the groups in DT order.
    pub fn with_active_tcs(mut self, tcs: u32) -> Self {
        self.active_tcs = tcs;
        self
    }

    fn tcs_reg(&self, tcs: u32, reg: u32) -> u32 {
        self.tcs_base + TCS_STRIDE * tcs + reg
    }

    fn cmd_reg(&self, tcs: u32, cmd: u32, reg: u32) -> u32 {
        self.tcs_reg(tcs, reg) + self.table.cmd_stride * cmd
    }

    /// Set or clear the AMC trigger, mirroring `__tcs_set_trigger`:
    /// clear TRIGGER, then clear ENABLE, then (when triggering) set
    /// ENABLE and set ENABLE|TRIGGER.
    fn set_trigger(&self, tcs: u32, trigger: bool) {
        let ctl = self.tcs_reg(tcs, self.table.control);
        self.regs.update32(ctl, AMC_TRIGGER, 0);
        self.regs.update32(ctl, AMC_ENABLE, 0);
        if trigger {
            self.regs.update32(ctl, AMC_ENABLE, AMC_ENABLE);
            self.regs.update32(ctl, AMC_TRIGGER, AMC_TRIGGER);
        }
    }

    /// `rpmh_rsc_send_data` for ACTIVE_ONLY: program TCS 0 with the
    /// commands and trigger it. When `wait` is set, poll for the TCS
    /// completion bit and tear the TCS down (mirroring `tcs_tx_done`);
    /// without `wait` the caller owns completion (Linux's
    /// `rpmh_write_async` shape). The teardown runs on timeout too so
    /// a timed-out TCS is left quiescent.
    pub async fn write_active<D: Delay + ?Sized>(
        &self,
        delay: &D,
        cmds: &[(u32, u32)],
        wait: bool,
    ) -> Result<(), RscError> {
        if cmds.is_empty() {
            return Err(RscError::Empty);
        }
        if cmds.len() > MAX_CMDS_PER_TCS {
            return Err(RscError::TooManyCmds);
        }
        let tcs = self.active_tcs;
        let msgid = MSGID_LEN | MSGID_WRITE | if wait { MSGID_RESP_REQ } else { 0 };
        for (i, (addr, data)) in cmds.iter().enumerate() {
            let i = i as u32;
            self.regs
                .write32(self.cmd_reg(tcs, i, self.table.cmd_msgid), msgid);
            self.regs
                .write32(self.cmd_reg(tcs, i, self.table.cmd_addr), *addr);
            self.regs
                .write32(self.cmd_reg(tcs, i, self.table.cmd_data), *data);
        }
        let enable_off = self.tcs_reg(tcs, self.table.cmd_enable);
        let mut mask = self.regs.read32(enable_off);
        for i in 0..cmds.len() {
            mask |= 1 << i;
        }
        self.regs.write32(enable_off, mask);
        self.set_trigger(tcs, true);
        if !wait {
            return Ok(());
        }
        let done = poll_reg(
            &self.regs,
            delay,
            self.table.irq_status,
            |v| v & (1 << tcs) != 0,
            POLL_SLEEP_US,
            POLL_TIMEOUT_US,
        )
        .await;
        // Teardown mirrors tcs_tx_done regardless of the outcome.
        self.set_trigger(tcs, false);
        self.regs.write32(enable_off, 0);
        self.regs.write32(self.table.irq_clear, 1 << tcs);
        done.map(|_| ()).map_err(|_| RscError::Timeout)
    }
}

/// Proxy-vote failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VoteError {
    /// No cmd-db entry for the resource id.
    UnknownResource,
    /// The rail name does not fit the 8-byte cmd-db id (`<rail>.lvl`).
    BadRail,
    /// The rail's cmd-db aux level map is empty or longer than
    /// `RPMH_ARC_MAX_LEVELS` (`rpmhpd_update_level_mapping` -EINVAL).
    BadLevels,
    /// The RSC transfer failed.
    Rsc(RscError),
}

/// `RPMH_ARC_MAX_LEVELS`.
const ARC_MAX_LEVELS: usize = 32;
/// `RPMH_REGULATOR_LEVEL_RETENTION` (dt-bindings `qcom,rpmhpd.h`).
const LEVEL_RETENTION: u16 = 16;

/// `rpmhpd_update_level_mapping` + `rpmhpd_set_performance_state(INT_MAX)`:
/// the aux data is one little-endian u16 vlvl per hlvl; trailing zero
/// entries after hlvl 0 end the map (a retention entry is skipped, not
/// treated as padding). An INT_MAX request is above every vlvl, so the
/// corner is `level_count - 1`. `None` for an empty or oversized map.
pub fn arc_max_corner(aux: &[u8]) -> Option<u32> {
    let mut count = aux.len() / 2;
    if count == 0 || count > ARC_MAX_LEVELS {
        return None;
    }
    for i in 0..count {
        let v = u16::from_le_bytes([aux[2 * i], aux[2 * i + 1]]);
        if v == LEVEL_RETENTION {
            continue;
        }
        if i > 0 && v == 0 {
            count = i;
            break;
        }
    }
    Some(count as u32 - 1)
}

/// The RPMh vote layer: cmd-db address lookup + RSC ACTIVE_ONLY writes.
#[derive(Debug)]
pub struct Rpmh<'a, R: RegIo> {
    db: CmdDb<'a>,
    rsc: Rsc<R>,
}

/// `clk-rpmh.c` ARC enable value for `bi_tcxo` (`DEFINE_CLK_RPMH_ARC`
/// `res_on_val` 0x3): the data word of an `xo.lvl` enable vote.
const XO_ON: u32 = 0x3;

impl<'a, R: RegIo> Rpmh<'a, R> {
    pub fn new(db: CmdDb<'a>, rsc: Rsc<R>) -> Self {
        Self { db, rsc }
    }

    /// One waited ACTIVE_ONLY vote: resolve `id` through cmd-db and
    /// write `(addr, value)` to the RSC (the `rpmh_write` shape used
    /// by both `rpmhpd` and `clk-rpmh` send paths).
    pub async fn vote<D: Delay + ?Sized>(
        &self,
        delay: &D,
        id: &str,
        value: u32,
    ) -> Result<(), VoteError> {
        let addr = self.db.read_addr(id).ok_or(VoteError::UnknownResource)?;
        self.rsc
            .write_active(delay, &[(addr, value)], true)
            .await
            .map_err(VoteError::Rsc)
    }

    /// A rail vote (`rpmhpd` shape): resource id `<rail>.lvl` (e.g.
    /// `cx.lvl`, `mx.lvl`) with a caller-supplied corner level. Levels
    /// come from the per-SoC DT `qcom,level` tables and are NOT pinned
    /// here — hardcoding one would be fabrication.
    pub async fn vote_rail<D: Delay + ?Sized>(
        &self,
        delay: &D,
        rail: &str,
        level: u32,
    ) -> Result<(), VoteError> {
        let mut id = [0u8; 8];
        let rb = rail.as_bytes();
        // `<rail>.lvl` must fit the 8-byte cmd-db id.
        if rb.len() + 4 > 8 {
            return Err(VoteError::BadRail);
        }
        id[..rb.len()].copy_from_slice(rb);
        id[rb.len()..rb.len() + 4].copy_from_slice(b".lvl");
        // The slice covers the whole rail plus `.lvl`, so it is valid
        // UTF-8 whenever `rail` is; vote() pads it to 8 bytes for the
        // lookup, matching Linux's `strtomem_pad`.
        let id = core::str::from_utf8(&id[..rb.len() + 4]).map_err(|_| VoteError::BadRail)?;
        self.vote(delay, id, level).await
    }

    /// The highest ARC corner (hlvl) of `<rail>.lvl`: what
    /// `dev_pm_genpd_set_performance_state(pd, INT_MAX)` selects in
    /// `rpmhpd_set_performance_state` (`qcom_pas_pds_enable`), from
    /// the cmd-db aux level map ([`arc_max_corner`]).
    pub fn rail_max_corner(&self, rail: &str) -> Result<u32, VoteError> {
        let mut id = [0u8; 8];
        let rb = rail.as_bytes();
        if rb.len() + 4 > 8 {
            return Err(VoteError::BadRail);
        }
        id[..rb.len()].copy_from_slice(rb);
        id[rb.len()..rb.len() + 4].copy_from_slice(b".lvl");
        let id = core::str::from_utf8(&id[..rb.len() + 4]).map_err(|_| VoteError::BadRail)?;
        let aux = self
            .db
            .read_aux_data(id)
            .ok_or(VoteError::UnknownResource)?;
        arc_max_corner(aux).ok_or(VoteError::BadLevels)
    }

    /// The `xo` clock vote (`clk-rpmh.c` ARC shape): `xo.lvl` with
    /// data 0x3 to enable, 0 to disable.
    pub async fn vote_xo<D: Delay + ?Sized>(&self, delay: &D, on: bool) -> Result<(), VoteError> {
        self.vote(delay, "xo.lvl", if on { XO_ON } else { 0 }).await
    }
}
