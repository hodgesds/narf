// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8821A notify state, independent of a native admission grant.
//! The generic algorithm is the chip's actual one/two-antenna source port.
//! The original owner keeps this state even after a partial/cancelled wait;
//! there is no rollback from helper-local RF backups and no replay on error.

use super::btc::{self, BtMpSource, BtcHal, LpsGate};
use super::h2c::Mailbox;
use crate::rtlwifi::btcoex::btc::{Algorithm, AmpduCfg, BtCoexist, Ctx, Packet, WifiInfo};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const WATCHDOG_MS: u64 = 2000;
pub const IN_4WAY_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug)]
pub enum Notify<'a> {
    Init,
    Ips(bool),
    Scan(bool),
    Connect(bool),
    Media(bool),
    Special(Packet),
    BtInfo(&'a [u8]),
    Periodical,
    Halt,
}

#[derive(Debug)]
pub struct Runtime<A: Algorithm> {
    pub algo: A,
    pub lps: LpsGate,
    pub ampdu: Option<AmpduCfg>,
    failed: bool,
    in_4way_since: Option<u64>,
    last_watchdog: Option<u64>,
}

impl<A: Algorithm> Runtime<A> {
    /// State construction performs no hardware effects and grants nothing.
    pub fn new(algo: A) -> Self {
        Self {
            algo,
            lps: LpsGate::default(),
            ampdu: None,
            failed: false,
            in_4way_since: None,
            last_watchdog: None,
        }
    }

    pub fn failed(&self) -> bool {
        self.failed
    }
    pub fn due(&self, now: u64) -> bool {
        self.last_watchdog
            .is_none_or(|last| now.saturating_sub(last) >= WATCHDOG_MS)
    }

    pub fn update_wifi(&mut self, btc: &mut BtCoexist, mut wifi: WifiInfo) {
        wifi.in_4way = btc.wifi.in_4way;
        btc.wifi = wifi;
    }

    pub fn eapol(&mut self, btc: &mut BtCoexist, now_ms: u64) {
        btc.wifi.in_4way = true;
        self.in_4way_since = Some(now_ms);
    }

    /// The caller encloses every poll and actual access in the current
    /// measured program, selected firmware and original PCI authority.
    /// `failed` is armed before the first effect and cleared only after all
    /// effects and re-entrant LPS notifications complete successfully.
    pub async fn notify<I: Io, M: BtMpSource>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        mp: &mut M,
        op: Notify<'_>,
    ) -> Result<(), Error> {
        if self.failed {
            return Err(Error::State);
        }
        self.failed = true;
        let mut hal = BtcHal::new(io, mailbox, &mut self.lps, mp);
        let result = {
            let mut cx = Ctx::new(btc, &mut hal);
            match op {
                Notify::Init => cx.init_hw_config(&mut self.algo).await,
                Notify::Ips(off) => cx.ips_notify(&mut self.algo, off).await,
                Notify::Scan(start) => cx.scan_notify(&mut self.algo, start).await,
                Notify::Connect(start) => cx.connect_notify(&mut self.algo, start).await,
                Notify::Media(link) => cx.media_status_notify(&mut self.algo, link).await,
                Notify::Special(packet) => cx.special_packet_notify(&mut self.algo, packet).await,
                Notify::BtInfo(body) => cx.bt_info_notify(&mut self.algo, body).await,
                Notify::Periodical => cx.periodical(&mut self.algo).await,
                Notify::Halt => cx.halt_notify(&mut self.algo).await,
            }
        };
        let notified = hal.lps_notified;
        if let Some(cfg) = hal.ampdu {
            self.ampdu = Some(cfg);
        }
        result?;
        Self::replay(&mut self.algo, btc, io, mailbox, &mut self.lps, notified).await?;
        self.failed = false;
        Ok(())
    }

    async fn replay<I: Io>(
        algo: &mut A,
        btc: &mut BtCoexist,
        io: &I,
        mailbox: &mut Mailbox,
        lps: &mut LpsGate,
        notified: btc::LpsNotified,
    ) -> Result<(), Error> {
        btc.statistics.cnt_lps_notify += notified.count - notified.modes().len() as u32;
        let mut none = btc::NoBtMp;
        let mut hal = BtcHal::new(io, mailbox, lps, &mut none);
        let mut cx = Ctx::new(btc, &mut hal);
        for &active in notified.modes() {
            cx.lps_notify(algo, active).await?;
        }
        Ok(())
    }

    /// Source 2-second watchdog and 30-second EAPOL timeout. The timestamp
    /// commits only after the notify completes; cancellation is terminal.
    pub async fn watchdog<I: Io, M: BtMpSource>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        mp: &mut M,
        now_ms: u64,
    ) -> Result<bool, Error> {
        if self
            .in_4way_since
            .is_some_and(|since| now_ms.saturating_sub(since) >= IN_4WAY_TIMEOUT_MS)
        {
            self.in_4way_since = None;
            btc.wifi.in_4way = false;
        }
        if self
            .last_watchdog
            .is_some_and(|last| now_ms.saturating_sub(last) < WATCHDOG_MS)
        {
            return Ok(false);
        }
        self.notify(btc, mailbox, io, mp, Notify::Periodical)
            .await?;
        self.last_watchdog = Some(now_ms);
        Ok(true)
    }

    pub async fn lps<I: Io>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        enter: bool,
    ) -> Result<Option<[u8; 7]>, Error> {
        use super::h2c::{self, BtLps};
        if self.failed {
            return Err(Error::State);
        }
        if !self.lps.fwctrl_lps
            || !self.lps.linked
            || self.lps.active != enter
            || enter && !self.lps.enter_allowed
        {
            return Ok(None);
        }
        self.failed = true;
        self.lps.active = !enter;
        if !self.lps.report_linked {
            self.failed = false;
            return Ok(None);
        }
        let ctrl = btc.lps_ctrl();
        let bt = ctrl.bt_ctrl_lps.then_some(BtLps {
            lps_on: ctrl.bt_lps_on,
            lps_val: ctrl.lps_val,
            rpwm_val: ctrl.rpwm_val,
        });
        let mut none = btc::NoBtMp;
        if enter {
            let mut hal = BtcHal::new(io, mailbox, &mut self.lps, &mut none);
            Ctx::new(btc, &mut hal)
                .lps_notify(&mut self.algo, false)
                .await?;
        }
        let cmd = if enter {
            h2c::fwlps_enter_bt(io, mailbox, bt).await?
        } else {
            h2c::fwlps_leave_bt(io, mailbox, bt).await?
        };
        btc.record_pwr_mode(&cmd);
        if !enter {
            let mut hal = BtcHal::new(io, mailbox, &mut self.lps, &mut none);
            Ctx::new(btc, &mut hal)
                .lps_notify(&mut self.algo, true)
                .await?;
        }
        self.failed = false;
        Ok(Some(cmd))
    }
}
