// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2012 - 2014 Realtek Corporation. All rights reserved.
//! RTL8821AE hardware access for the source RTL8821A coexistence programs.
//! No RTL8723B RF, mailbox or LPS implementation is used by this adapter.
//! The owner supplies the retained single mailbox, original RF backups and
//! genuine RX C2H stream. Native access must be enclosed by its joint grant.

use super::{c2h, h2c, phy};
use crate::rtlwifi::btcoex::btc::{AmpduCfg, Hal, LpsCtrl, MpReport};
use crate::rtlwifi::firmware_transport::Io;
use crate::rtlwifi::prepare::Error;

pub const C2H_MAX: usize = c2h::C2H_DATA_OFFSET + 16;

/// A finite arrival queue and a separate deferred queue. `defer_c2h` must
/// never put the packet back in the queue polled by this same MP wait.
pub trait C2hSource {
    /// Bound each millisecond drain even if the device produces C2H forever.
    fn begin_round(&mut self) {}
    fn poll_c2h(&mut self, out: &mut [u8; C2H_MAX]) -> Result<Option<usize>, Error>;
    fn defer_c2h(&mut self, packet: &[u8]) -> Result<(), Error>;
}

#[allow(async_fn_in_trait)]
pub trait BtMpSource {
    async fn next_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error>;
}

/// The version response's full source value/build must really be present.
/// Padding a short response cannot establish a new qualification identity.
pub(crate) fn version_report(body: &[u8]) -> Result<Option<(u16, u8)>, Error> {
    if body.len() < 3
        || body[0] != 1
        || body[2] >> 4 != crate::rtlwifi::btcoex::btc::BT_SEQ_GET_BT_VERSION
    {
        return Ok(None);
    }
    if body.len() < 6 {
        return Err(Error::Descriptor);
    }
    Ok(Some((u16::from_le_bytes([body[3], body[4]]), body[5])))
}

/// Before RX is enabled the source initialization's MP queries really time
/// out; this object supplies no firmware version or synthetic completion.
pub struct NoBtMp;
impl BtMpSource for NoBtMp {
    async fn next_bt_mp(&mut self, _: u32) -> Result<Option<MpReport>, Error> {
        Ok(None)
    }
}

pub struct RxBtMp<'a, I: Io, S: C2hSource> {
    pub io: &'a I,
    pub source: &'a mut S,
}
impl<I: Io, S: C2hSource> BtMpSource for RxBtMp<'_, I, S> {
    async fn next_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error> {
        let mut bytes = [0; C2H_MAX];
        for waited in 0..=wait_ms {
            self.source.begin_round();
            while let Some(n) = self.source.poll_c2h(&mut bytes)? {
                let packet = bytes.get(..n).ok_or(Error::Descriptor)?;
                match c2h::parse(packet) {
                    Ok(c2h::Event::BtMp(body)) => {
                        version_report(body)?;
                        return Ok(Some(MpReport::new(body)));
                    }
                    Ok(_) => self.source.defer_c2h(packet)?,
                    Err(_) => {}
                }
            }
            if waited != wait_ms {
                self.io.delay_us(1000).await;
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LpsGate {
    pub fwctrl_lps: bool,
    pub linked: bool,
    pub report_linked: bool,
    pub enter_allowed: bool,
    pub active: bool,
}
impl Default for LpsGate {
    fn default() -> Self {
        Self {
            fwctrl_lps: true,
            linked: false,
            report_linked: false,
            enter_allowed: false,
            active: true,
        }
    }
}

/// Deferred re-entrant `btc_lps_notify` calls. The source 8821A handlers
/// only update under_lps; the final state and exact statistics survive.
#[derive(Clone, Copy, Debug, Default)]
pub struct LpsNotified {
    modes: [bool; 4],
    pub count: u32,
}
impl LpsNotified {
    fn push(&mut self, active: bool) {
        if self.count < 4 {
            self.modes[self.count as usize] = active;
        } else {
            self.modes.copy_within(1.., 0);
            self.modes[3] = active;
        }
        self.count = self.count.saturating_add(1);
    }
    pub fn modes(&self) -> &[bool] {
        &self.modes[..(self.count as usize).min(4)]
    }
}

pub struct BtcHal<'a, I: Io, M: BtMpSource> {
    pub io: &'a I,
    pub mailbox: &'a mut h2c::Mailbox,
    pub lps: &'a mut LpsGate,
    pub mp: &'a mut M,
    pub ampdu: Option<AmpduCfg>,
    pub lps_notified: LpsNotified,
}
impl<'a, I: Io, M: BtMpSource> BtcHal<'a, I, M> {
    pub fn new(
        io: &'a I,
        mailbox: &'a mut h2c::Mailbox,
        lps: &'a mut LpsGate,
        mp: &'a mut M,
    ) -> Self {
        Self {
            io,
            mailbox,
            lps,
            mp,
            ampdu: None,
            lps_notified: LpsNotified::default(),
        }
    }
    pub fn enter_sends(&self) -> bool {
        self.lps.fwctrl_lps && self.lps.enter_allowed && self.lps.linked && self.lps.report_linked
    }
    fn bt(ctrl: LpsCtrl) -> Option<h2c::BtLps> {
        ctrl.bt_ctrl_lps.then_some(h2c::BtLps {
            lps_on: ctrl.bt_lps_on,
            lps_val: ctrl.lps_val,
            rpwm_val: ctrl.rpwm_val,
        })
    }
}

impl<I: Io, M: BtMpSource> Hal for BtcHal<'_, I, M> {
    fn read8(&mut self, at: u16) -> Result<u8, Error> {
        Ok(self.io.read8(at)?)
    }
    fn read16(&mut self, at: u16) -> Result<u16, Error> {
        Ok(self.io.read16(at)?)
    }
    fn read32(&mut self, at: u16) -> Result<u32, Error> {
        Ok(self.io.read32(at)?)
    }
    fn write8(&mut self, at: u16, value: u8) -> Result<(), Error> {
        Ok(self.io.write8(at, value)?)
    }
    fn write16(&mut self, at: u16, value: u16) -> Result<(), Error> {
        Ok(self.io.write16(at, value)?)
    }
    fn write32(&mut self, at: u16, value: u32) -> Result<(), Error> {
        Ok(self.io.write32(at, value)?)
    }
    async fn set_rf(&mut self, path: u8, at: u32, mask: u32, value: u32) -> Result<(), Error> {
        if path != 0 || mask == 0 {
            return Err(Error::Address);
        }
        phy::set_rf(self.io, at, mask, value).await
    }
    async fn get_rf(&mut self, path: u8, at: u32, mask: u32) -> Result<u32, Error> {
        if path != 0 || mask == 0 {
            return Err(Error::Address);
        }
        Ok((phy::rf_read(self.io, at).await? & mask) >> mask.trailing_zeros())
    }
    async fn fill_h2c(&mut self, id: u8, bytes: &[u8]) -> Result<(), Error> {
        self.mailbox.fill(self.io, id, bytes).await
    }
    async fn wait_bt_mp(&mut self, wait_ms: u32) -> Result<Option<MpReport>, Error> {
        self.mp.next_bt_mp(wait_ms).await
    }
    async fn delay_ms(&mut self, ms: u32) {
        self.io.delay_us(u64::from(ms) * 1000).await
    }
    async fn lps_leave(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        if !self.lps.fwctrl_lps || self.lps.active || !self.lps.linked {
            return Ok(None);
        }
        self.lps.active = true;
        if !self.lps.report_linked {
            return Ok(None);
        }
        let cmd = h2c::fwlps_leave_bt(self.io, self.mailbox, Self::bt(ctrl)).await?;
        self.lps_notified.push(true);
        Ok(Some(cmd))
    }
    async fn lps_enter(&mut self, ctrl: LpsCtrl) -> Result<Option<[u8; 7]>, Error> {
        if !self.lps.fwctrl_lps || !self.lps.enter_allowed || !self.lps.linked {
            return Ok(None);
        }
        self.lps.active = false;
        if !self.lps.report_linked {
            return Ok(None);
        }
        self.lps_notified.push(false);
        let cmd = h2c::fwlps_enter_bt(self.io, self.mailbox, Self::bt(ctrl)).await?;
        Ok(Some(cmd))
    }
    fn rx_ampdu_apply(&mut self, cfg: AmpduCfg) {
        self.ampdu = Some(cfg);
    }
    fn now_ms(&mut self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000_000
    }
}
