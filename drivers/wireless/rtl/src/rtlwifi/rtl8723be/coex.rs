// SPDX-License-Identifier: GPL-2.0-or-later
//! The RTL8723BE Bluetooth-coexistence owner: `rtlpriv->btcoexist` with the
//! `rtl_btc_ops` call sites of the Linux driver.
//!
//! [`Owner`] holds `struct btc_coexist` ([`BtCoexist`]), the RTL8723B
//! `exhalbtc_*` dispatch ([`Rtl8723b`], chosen by `btdm_ant_num` on every
//! notify), the chip's single H2C [`Mailbox`] (`rtlhal->last_hmeboxnum`,
//! shared by every H2C sender) and the `ps.c` [`LpsGate`].
//! `get_btc_status()` is always true on this chip (`rtl8723be/sw.c`), so
//! every call site below runs on every board, `bt_exist` or not.
//!
//! | Linux call site | Method |
//! |---|---|
//! | `pci.c::rtl_pci_start` → `btc_init_variables` | [`Owner::bind`] |
//! | `hw.c:827` `_rtl8723be_init_mac` → `btc_power_on_setting` | [`Owner::power_on_setting`] |
//! | `hw.c:2708` `rtl8723be_bt_hw_init` → `btc_init_hw_config` | [`Owner::init_hw_config`] |
//! | `ps.c:239` `_rtl_ps_inactive_ps` (`ERFOFF`) / `ps.c:284` `rtl_ips_nic_on` (`ERFON`) → `btc_ips_notify` | [`Owner::ips`] |
//! | `ps.c:368` / `ps.c:375` `rtl_lps_set_psmode` → `btc_lps_notify` + `rtl8723be_set_fw_pwrmode_cmd` (`btc_is_bt_ctrl_lps` …, `btc_record_pwr_mode`) | [`Owner::lps_leave`] / [`Owner::lps_enter`] |
//! | `core.c:1425` / `core.c:1478` `rtl_op_sw_scan_{start,complete}` → `btc_scan_notify` | [`Owner::scan`] |
//! | `core.c:1181` `rtl_op_bss_info_changed` (`BSS_CHANGED_ASSOC`) → `btc_mediastatus_notify` | [`Owner::media_status`] |
//! | `exhalbtc_connect_notify` (association start / finish) | [`Owner::connect`] |
//! | `base.c:1455` `setup_special_tx` → `btc_special_packet_notify` (and `base.c:1539` EAPOL `in_4way`) | [`Owner::special_packet`] / [`Owner::eapol`] |
//! | `base.c:2205` `rtl_watchdog_wq_callback` → `btc_periodical` + the `in_4way` timeout | [`Owner::watchdog`] |
//! | `base.c:2313` / `base.c:2319` `rtl_c2h_content_parsing` → `btc_btinfo_notify` / `btc_btmpinfo_notify` | [`Owner::c2h`] |
//! | `pci.c:1774` `rtl_pci_stop` → `btc_halt_notify` + `btc_deinit_variables` | [`Owner::halt`] |
//!
//! Differences from Linux: access errors propagate and end the notify; the
//! re-entrant `btc_lps_notify` an algorithm-requested LPS change makes is
//! replayed after the outer notify ([`super::btc::LpsNotified`]); the
//! watchdog cadence (`RTL_WATCH_DOG_TIME`, 2 s) is enforced here from
//! the caller's monotonic clock rather than by a kernel timer.

use super::btc::{BtMpSource, BtcHal, C2hSource, LpsGate, RxBtMp};
use super::c2h;
use super::h2c::{fwlps_enter, fwlps_leave, BtLps, Mailbox};
use crate::rtlwifi::btcoex::b8723b2ant::Rtl8723b;
use crate::rtlwifi::btcoex::btc::{AmpduCfg, BtCoexist, Ctx, HwPg, Packet, WifiInfo};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

/// `RTL_WATCH_DOG_TIME` (ms).
pub const WATCHDOG_MS: u64 = 2000;
/// `IN_4WAY_TIMEOUT_TIME` (ms).
pub const IN_4WAY_TIMEOUT_MS: u64 = 30_000;

/// One C2H packet's effect for the caller (`rtl_c2h_content_parsing`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum C2h {
    /// `rtl_tx_report_handler` (V1): the packet owner's.
    TxReport { sn: u16, st: u8, retry: u8 },
    /// BT info / BT MP: consumed by coexistence.
    Coex,
    /// RA report, debug, TXBF, unknown: consumed without effect.
    Other,
}

/// The RTL8723BE coexistence owner (see the module documentation).
#[derive(Debug)]
pub struct Owner {
    pub btc: BtCoexist,
    pub algo: Rtl8723b,
    pub mailbox: Mailbox,
    pub lps: LpsGate,
    /// The last `rtl_rx_ampdu_apply` configuration for the station owner.
    pub ampdu: Option<AmpduCfg>,
    /// `btc_info.in_4way_ts` (ms).
    in_4way_since: Option<u64>,
    /// The last watchdog `btc_periodical` (ms).
    last_watchdog: Option<u64>,
}

impl Owner {
    /// `rtl_btc_init_variables` (`rtl_pci_start`, before `hw_init`) from the
    /// `rtl8723be_read_bt_coexist_info_from_hwpg` facts. `sw.c` sets
    /// `fwctrl_lps = true`.
    pub fn bind(pg: HwPg) -> Self {
        Self {
            btc: BtCoexist::bind(pg),
            algo: Rtl8723b::default(),
            mailbox: Mailbox::default(),
            lps: LpsGate {
                fwctrl_lps: true,
                linked: false,
                report_linked: false,
                enter_allowed: false,
                active: true,
            },
            ampdu: None,
            in_4way_since: None,
            last_watchdog: None,
        }
    }

    /// The driver state the next notify reads (`halbtc_get`); `in_4way` is
    /// this owner's.
    pub fn update_wifi(&mut self, mut wifi: WifiInfo) {
        wifi.in_4way = self.btc.wifi.in_4way;
        self.btc.wifi = wifi;
    }

    /// One `Ctx` borrow over `io` and `mp`, then the replay of any
    /// re-entrant LPS notify the algorithm caused.
    async fn run<I: Io, M: BtMpSource>(
        &mut self,
        io: &I,
        mp: &mut M,
        op: Op<'_>,
    ) -> Result<(), Error> {
        let mut hal = BtcHal::new(io, &mut self.mailbox, &mut self.lps, mp);
        let result = {
            let mut cx = Ctx::new(&mut self.btc, &mut hal);
            let a = &mut self.algo;
            match op {
                Op::PowerOn => cx.power_on_setting(a).await,
                Op::InitHwConfig => cx.init_hw_config(a).await,
                Op::Ips(rf_off) => cx.ips_notify(a, rf_off).await,
                Op::Lps(active) => cx.lps_notify(a, active).await,
                Op::Scan(start) => cx.scan_notify(a, start).await,
                Op::Connect(start) => cx.connect_notify(a, start).await,
                Op::Media(connect) => cx.media_status_notify(a, connect).await,
                Op::Special(pkt) => cx.special_packet_notify(a, pkt).await,
                Op::BtInfo(buf) => cx.bt_info_notify(a, buf).await,
                Op::Periodical => cx.periodical(a).await,
                Op::Halt => cx.halt_notify(a).await,
            }
        };
        let notified = hal.lps_notified;
        if let Some(cfg) = hal.ampdu {
            self.ampdu = Some(cfg);
        }
        result?;
        self.replay_lps(io, notified).await
    }

    async fn replay_lps<I: Io>(
        &mut self,
        io: &I,
        notified: super::btc::LpsNotified,
    ) -> Result<(), Error> {
        if notified.count == 0 {
            return Ok(());
        }
        let extra = notified.count - notified.modes().len() as u32;
        self.btc.statistics.cnt_lps_notify += extra;
        let mut none = super::btc::NoBtMp;
        let mut hal = BtcHal::new(io, &mut self.mailbox, &mut self.lps, &mut none);
        let mut cx = Ctx::new(&mut self.btc, &mut hal);
        for &active in notified.modes() {
            cx.lps_notify(&mut self.algo, active).await?;
        }
        Ok(())
    }

    /// `hw.c:827`: after `RTL8723_NIC_ENABLE_FLOW`, before
    /// `REG_MULTI_FUNC_CTRL |= BIT(3)`. No firmware runs yet.
    pub async fn power_on_setting<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.run(io, &mut super::btc::NoBtMp, Op::PowerOn).await
    }

    /// `hw.c:2708` `rtl8723be_bt_hw_init`: after the station address and
    /// before the `ERFON` block (the firmware is running; the RX ring is
    /// not, so MP waits time out as no C2H can arrive).
    pub async fn init_hw_config<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.run(io, &mut super::btc::NoBtMp, Op::InitHwConfig)
            .await
    }

    /// `btc_ips_notify(ERFOFF)` (`ps.c:239`, before the NIC off) or
    /// `btc_ips_notify(ERFON)` (`ps.c:284`, after the NIC on; adds the
    /// scan start + finish).
    pub async fn ips<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        rf_off: bool,
    ) -> Result<(), Error> {
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Ips(rf_off)).await
    }

    /// The BT LPS control `rtl8723be_set_fw_pwrmode_cmd` reads.
    pub fn bt_lps(&self) -> Option<BtLps> {
        let ctrl = self.btc.lps_ctrl();
        ctrl.bt_ctrl_lps.then_some(BtLps {
            lps_on: ctrl.bt_lps_on,
            lps_val: ctrl.lps_val,
            rpwm_val: ctrl.rpwm_val,
        })
    }

    /// `rtl_lps_leave_core` → `rtl_lps_set_psmode(EACTIVE)` (`ps.c:368`):
    /// `HW_VAR_FW_LPS_ACTION` (`_rtl8723be_fwlps_leave` with the BT LPS
    /// form, recorded by `btc_record_pwr_mode`), then
    /// `btc_lps_notify(EACTIVE)`. Returns the `SETPWRMODE` body sent.
    pub async fn lps_leave<I: Io>(&mut self, io: &I) -> Result<Option<[u8; 7]>, Error> {
        let l = self.lps;
        if !l.fwctrl_lps || l.active || !l.linked {
            return Ok(None);
        }
        self.lps.active = true;
        if !l.report_linked {
            return Ok(None);
        }
        let bt = self.bt_lps();
        let cmd = fwlps_leave(io, &mut self.mailbox, bt).await?;
        self.btc.record_pwr_mode(&cmd);
        self.run(io, &mut super::btc::NoBtMp, Op::Lps(true)).await?;
        Ok(Some(cmd))
    }

    /// `rtl_lps_enter_core` → `rtl_lps_set_psmode(EAUTOPS)` (`ps.c:375`):
    /// `btc_lps_notify(EAUTOPS)`, then `HW_VAR_FW_LPS_ACTION`
    /// (`_rtl8723be_fwlps_enter`, recorded). Returns the body sent.
    pub async fn lps_enter<I: Io>(&mut self, io: &I) -> Result<Option<[u8; 7]>, Error> {
        let l = self.lps;
        if !l.fwctrl_lps || !l.enter_allowed || !l.linked {
            return Ok(None);
        }
        self.lps.active = false;
        if !l.report_linked {
            return Ok(None);
        }
        self.run(io, &mut super::btc::NoBtMp, Op::Lps(false))
            .await?;
        let bt = self.bt_lps();
        let cmd = fwlps_enter(io, &mut self.mailbox, bt).await?;
        self.btc.record_pwr_mode(&cmd);
        Ok(Some(cmd))
    }

    /// `btc_scan_notify(1)` (`core.c:1425`) / `(0)` (`core.c:1478`).
    pub async fn scan<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        start: bool,
    ) -> Result<(), Error> {
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Scan(start)).await
    }

    /// `exhalbtc_connect_notify(ASSOCIATE_START / FINISH)`.
    pub async fn connect<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        start: bool,
    ) -> Result<(), Error> {
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Connect(start)).await
    }

    /// `btc_mediastatus_notify` (`core.c:1181`, `BSS_CHANGED_ASSOC`).
    pub async fn media_status<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        connect: bool,
    ) -> Result<(), Error> {
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Media(connect)).await
    }

    /// `base.c:1539`: an EAPOL frame (either direction) marks `in_4way`.
    pub fn eapol(&mut self, now_ms: u64) {
        self.btc.wifi.in_4way = true;
        self.in_4way_since = Some(now_ms);
    }

    /// `setup_special_tx` (`base.c:1455`): the special-packet notify; the
    /// caller then runs `rtl_lps_leave` ([`Self::lps_leave`]).
    pub async fn special_packet<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        pkt: Packet,
    ) -> Result<(), Error> {
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Special(pkt)).await
    }

    /// `rtl_watchdog_wq_callback` (`base.c:2205`): `btc_periodical`, then
    /// the 30 s `in_4way` timeout. Runs at most once per
    /// [`WATCHDOG_MS`]; returns whether it ran.
    pub async fn watchdog<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h: &mut S,
        now_ms: u64,
    ) -> Result<bool, Error> {
        if self
            .last_watchdog
            .is_some_and(|last| now_ms.wrapping_sub(last) < WATCHDOG_MS)
        {
            return Ok(false);
        }
        self.last_watchdog = Some(now_ms);
        let mut mp = RxBtMp { io, source: c2h };
        self.run(io, &mut mp, Op::Periodical).await?;
        if self.btc.wifi.in_4way
            && self
                .in_4way_since
                .is_none_or(|ts| now_ms.wrapping_sub(ts) > IN_4WAY_TIMEOUT_MS)
        {
            self.btc.wifi.in_4way = false;
            self.in_4way_since = None;
        }
        Ok(true)
    }

    /// `rtl_c2h_content_parsing` for one C2H packet (`base.c:2313` BT info →
    /// `btc_btinfo_notify`, `base.c:2319` BT MP → `btc_btmpinfo_notify`;
    /// an MP body outside an MP wait only updates `bt_info`, as Linux's
    /// `complete()` without a waiter). MP waits inside the BT-info notify
    /// poll `c2h`.
    pub async fn c2h<I: Io, S: C2hSource>(
        &mut self,
        io: &I,
        c2h_source: &mut S,
        packet: &[u8],
    ) -> Result<C2h, Error> {
        let Ok(event) = c2h::parse(packet) else {
            return Ok(C2h::Other);
        };
        match event {
            c2h::Event::TxReport { sn, st, retry } => Ok(C2h::TxReport { sn, st, retry }),
            c2h::Event::BtInfo(body) => {
                // `rtl_c2h_content_parsing` hands at most the 16-byte buffer.
                let mut buf = [0u8; 16];
                let n = body.len().min(buf.len());
                buf[..n].copy_from_slice(&body[..n]);
                let mut mp = RxBtMp {
                    io,
                    source: c2h_source,
                };
                self.run(io, &mut mp, Op::BtInfo(&buf[..n])).await?;
                Ok(C2h::Coex)
            }
            c2h::Event::BtMp(body) => {
                self.btc.btmpinfo_notify(body);
                Ok(C2h::Coex)
            }
            c2h::Event::Other(_) => Ok(C2h::Other),
        }
    }

    /// `rtl_pci_stop` (`pci.c:1774`): `btc_halt_notify` (which unbinds;
    /// `btc_deinit_variables` has nothing more to release here). Runs
    /// before interrupts and the adapter are disabled.
    pub async fn halt<I: Io>(&mut self, io: &I) -> Result<(), Error> {
        self.run(io, &mut super::btc::NoBtMp, Op::Halt).await
    }
}

#[derive(Clone, Copy)]
enum Op<'a> {
    PowerOn,
    InitHwConfig,
    Ips(bool),
    Lps(bool),
    Scan(bool),
    Connect(bool),
    Media(bool),
    Special(Packet),
    BtInfo(&'a [u8]),
    Periodical,
    Halt,
}
