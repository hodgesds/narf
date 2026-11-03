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

/// The largest C2H packet the RX path hands over (`C2H_DATA_OFFSET` plus
/// the 16-byte command buffer `rtl_c2h_content_parsing` reads).
pub const C2H_MAX: usize = super::c2h::C2H_DATA_OFFSET + 16;

/// The owner's C2H packet stream (`rpt_sel != 0` RX statuses, from the
/// payload offset, the status length).
pub trait C2hSource {
    /// The next pending C2H packet copied into `out`, if one has arrived.
    fn poll_c2h(&mut self, out: &mut [u8; C2H_MAX]) -> Result<Option<usize>, Error>;
    /// Hand a C2H packet that is not a `BT_MP` body back to the owner's
    /// queue (`rtl_c2hcmd_enqueue`: it is processed after the MP wait, as
    /// Linux's C2H work item runs after `rtl_c2h_fast_cmd`).
    fn defer_c2h(&mut self, packet: &[u8]) -> Result<(), Error>;
}

/// No RX ring attached (before packet start): nothing ever arrives.
#[derive(Debug)]
pub struct NoC2h;

impl C2hSource for NoC2h {
    fn poll_c2h(&mut self, _out: &mut [u8; C2H_MAX]) -> Result<Option<usize>, Error> {
        Ok(None)
    }
    fn defer_c2h(&mut self, _packet: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

/// `bt_mp_comp` over the RX ring: `rtl_c2h_fast_cmd` takes `C2H_BT_MP`
/// inline (`pci.c` RX → `rtl_c2hcmd_enqueue`), so the wait polls the C2H
/// stream every millisecond for up to `wait_ms` and returns the first
/// `BT_MP` body; every other C2H packet goes back through
/// [`C2hSource::defer_c2h`].
#[derive(Debug)]
pub struct RxBtMp<'a, I: Io, S: C2hSource> {
    pub io: &'a I,
    pub source: &'a mut S,
}

impl<I: Io, S: C2hSource> BtMpSource for RxBtMp<'_, I, S> {
    async fn next_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error> {
        let mut buf = [0u8; C2H_MAX];
        let mut waited = 0u32;
        loop {
            while let Some(n) = self.source.poll_c2h(&mut buf)? {
                let packet = &buf[..n.min(C2H_MAX)];
                match super::c2h::parse(packet) {
                    Ok(super::c2h::Event::BtMp(body)) => return Ok(Some(MpReport::new(body))),
                    Ok(_) => self.source.defer_c2h(packet)?,
                    // `rtl_c2hcmd_enqueue` drops a malformed packet.
                    Err(_) => {}
                }
            }
            if waited >= wait_ms {
                return Ok(None);
            }
            self.io.delay_us(1000).await;
            waited += 1;
        }
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
    /// `rtl_lps_set_psmode` calls `btc_lps_notify` on every mode it sends,
    /// also when the coexistence algorithm itself asked for the LPS change
    /// (re-entering `exhalbtc_lps_notify`). The algorithm is borrowed at
    /// that point, so each such notify is recorded here (`true` = EACTIVE)
    /// and replayed by the owner after the outer notify returns. Both 8723B
    /// handlers only set `coex_sta->under_lps` there, which nothing but
    /// debugfs reads, so the deferral is not observable on the air.
    pub lps_notified: LpsNotified,
}

/// The re-entrant `btc_lps_notify` calls one borrow made (bounded; the
/// count keeps the statistic exact when more than [`LpsNotified::CAP`]
/// arrive, the last ones are kept).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LpsNotified {
    modes: [bool; Self::CAP],
    pub count: u32,
}

impl LpsNotified {
    pub const CAP: usize = 4;
    fn push(&mut self, active: bool) {
        let n = self.count as usize;
        if n < Self::CAP {
            self.modes[n] = active;
        } else {
            self.modes.copy_within(1.., 0);
            self.modes[Self::CAP - 1] = active;
        }
        self.count = self.count.saturating_add(1);
    }
    /// The recorded modes, oldest first.
    pub fn modes(&self) -> &[bool] {
        &self.modes[..(self.count as usize).min(Self::CAP)]
    }
}

impl<'a, I: Io, M: BtMpSource> BtcHal<'a, I, M> {
    pub fn new(io: &'a I, mailbox: &'a mut Mailbox, lps: &'a mut LpsGate, mp: &'a mut M) -> Self {
        Self {
            io,
            mailbox,
            lps,
            mp,
            ampdu: None,
            lps_notified: LpsNotified::default(),
        }
    }

    /// `rtl_lps_enter_core`'s gates up to `rtl_lps_set_psmode(EAUTOPS)`
    /// sending a command.
    pub fn enter_sends(&self) -> bool {
        self.lps.fwctrl_lps && self.lps.enter_allowed && self.lps.linked && self.can_set_psmode()
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
        self.lps_notified.push(true);
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
        self.lps_notified.push(false);
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
