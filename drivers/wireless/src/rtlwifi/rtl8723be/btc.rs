// SPDX-License-Identifier: GPL-2.0-or-later
//! The `btc_coexist` accessors over the RTL8723BE owner
//! (`halbtcoutsrc.c::halbtc_read_*` / `halbtc_write_*` / `halbtc_set_rfreg`
//! / `halbtc_fill_h2c_cmd`, `rtl_lps_{enter,leave}` through
//! `rtl8723be_set_fw_pwrmode_cmd`).
//!
//! - `rtl_read_word`: [`Io`] has no 16-bit read; the word is extracted from
//!   the aligned dword (the coexistence words read are the 0xf90-0xfba
//!   priority counters, 0x42a and `REG_SYS_FUNC_EN` 0x2, none read-to-clear).
//!   A word straddling a dword boundary is refused.
//! - `rtl_write_word` is [`Io::write16`] (exact width; refused by adapters
//!   without one).
//! - `fill_h2c_cmd` is [`Mailbox::fill`] (`_rtl8723be_fill_h2c_command`).
//! - `rtl_lps_leave` / `rtl_lps_enter` are `rtl_lps_set_psmode` over
//!   [`LpsGate`] (the `ps.c` conditions the station owner tracks) and
//!   [`fwlps_leave`] / [`fwlps_enter`] with the BT LPS control
//!   (`rtl_btc_is_bt_ctrl_lps`).
//! - The C2H `BT_MP` wait is the owner's [`BtMpSource`] (the RX ring is
//!   the owner's).

use super::h2c::{fwlps_enter, fwlps_leave, BtLps, Mailbox};
use super::phy::{get_rf, set_rf, Path};
use crate::rtlwifi::btcoex::btc::{AmpduCfg, Hal, LpsCtrl, MpReport};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// Where the owner delivers C2H `BT_MP` bodies while a coexistence MP
/// operation waits.
#[allow(async_fn_in_trait)]
pub trait BtMpSource {
    async fn next_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error>;
}

/// No RX path attached: every wait times out.
#[derive(Debug)]
pub struct NoBtMp;

impl BtMpSource for NoBtMp {
    async fn next_bt_mp(&mut self, _wait_ms: u32) -> Result<Option<MpReport>, Error> {
        Ok(None)
    }
}

/// The `ps.c` state `rtl_lps_enter_core` / `rtl_lps_leave_core` /
/// `rtl_lps_set_psmode` read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpsGate {
    /// `ppsc->fwctrl_lps` (`sw.c`: true).
    pub fwctrl_lps: bool,
    /// `mac->link_state == MAC80211_LINKED` (INFRA station).
    pub linked: bool,
    /// `ppsc->report_linked`.
    pub report_linked: bool,
    /// `rtl_lps_enter_core` gates: `!sec.being_setkey`,
    /// `!link_info.busytraffic`, `cnt_after_linked >= 5`.
    pub enter_allowed: bool,
    /// `ppsc->dot11_psmode == EACTIVE`.
    pub active: bool,
}

/// `btc_coexist` accessors over one RTL8723BE owner borrow.
#[derive(Debug)]
pub struct BtcHal<'a, I: Io, M: BtMpSource> {
    pub io: &'a I,
    pub mailbox: &'a mut Mailbox,
    pub lps: &'a mut LpsGate,
    pub mp: &'a mut M,
    /// The last `rtl_rx_ampdu_apply` configuration (the station owner
    /// applies it to the RX BA sessions).
    pub ampdu: Option<AmpduCfg>,
}

impl<'a, I: Io, M: BtMpSource> BtcHal<'a, I, M> {
    pub fn new(io: &'a I, mailbox: &'a mut Mailbox, lps: &'a mut LpsGate, mp: &'a mut M) -> Self {
        Self {
            io,
            mailbox,
            lps,
            mp,
            ampdu: None,
        }
    }

    fn bt(ctrl: LpsCtrl) -> Option<BtLps> {
        ctrl.bt_ctrl_lps.then_some(BtLps {
            lps_on: ctrl.bt_lps_on,
            lps_val: ctrl.lps_val,
            rpwm_val: ctrl.rpwm_val,
        })
    }

    /// `rtl_lps_set_psmode` preconditions (INFRA, linked, FW LPS reported).
    fn can_set_psmode(&self) -> bool {
        self.lps.linked && self.lps.fwctrl_lps && self.lps.report_linked
    }
}

fn path(p: u8) -> Path {
    if p == 0 {
        Path::A
    } else {
        Path::B
    }
}

impl<I: Io, M: BtMpSource> Hal for BtcHal<'_, I, M> {
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        Ok(self.io.read8(reg)?)
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        let offset = reg & 3;
        if offset == 3 {
            return Err(Error::Address);
        }
        let dword = self.io.read32(reg & !3)?;
        Ok((dword >> (8 * offset)) as u16)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        Ok(self.io.read32(reg)?)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        Ok(self.io.write8(reg, value)?)
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        Ok(self.io.write16(reg, value)?)
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        Ok(self.io.write32(reg, value)?)
    }
    async fn set_rf(&mut self, p: u8, reg: u32, mask: u32, data: u32) -> Result<(), Error> {
        set_rf(self.io, path(p), reg, mask, data).await
    }
    async fn get_rf(&mut self, p: u8, reg: u32, mask: u32) -> Result<u32, Error> {
        get_rf(self.io, path(p), reg, mask).await
    }
    async fn fill_h2c(&mut self, id: u8, cmd: &[u8]) -> Result<(), Error> {
        self.mailbox.fill(self.io, id, cmd).await
    }
    async fn wait_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error> {
        self.mp.next_bt_mp(wait_ms).await
    }
    async fn delay_ms(&mut self, ms: u32) {
        self.io.delay_us(u64::from(ms) * 1000).await
    }
    /// `rtl_lps_leave_core`: only when `dot11_psmode != EACTIVE`.
    async fn lps_leave(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        if !self.lps.fwctrl_lps || self.lps.active || !self.lps.linked {
            return Ok(None);
        }
        self.lps.active = true;
        if !self.can_set_psmode() {
            return Ok(None);
        }
        let cmd = fwlps_leave(self.io, self.mailbox, Self::bt(ctrl)).await?;
        Ok(Some(cmd))
    }
    /// `rtl_lps_enter_core` → `rtl_lps_set_psmode(EAUTOPS)`.
    async fn lps_enter(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        if !self.lps.fwctrl_lps || !self.lps.enter_allowed || !self.lps.linked {
            return Ok(None);
        }
        self.lps.active = false;
        if !self.can_set_psmode() {
            return Ok(None);
        }
        let cmd = fwlps_enter(self.io, self.mailbox, Self::bt(ctrl)).await?;
        Ok(Some(cmd))
    }
    fn rx_ampdu_apply(&mut self, cfg: AmpduCfg) {
        self.ampdu = Some(cfg);
    }
    fn now_ms(&mut self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
}
