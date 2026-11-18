// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual EFUSE antenna dispatch; algorithms own disjoint source histories.
use super::{
    btc::{BtMpSource, LpsGate},
    coex_runtime::{Notify, Runtime},
    h2c::Mailbox,
};
use crate::rtlwifi::{
    btcoex::{
        b8821a1ant::B8821a1Ant,
        b8821a2ant::B8821a2Ant,
        btc::{AmpduCfg, BtCoexist},
    },
    firmware_transport::Io,
    prepare::Error,
};
use alloc::boxed::Box;

#[derive(Debug)]
pub(in crate::rtlwifi) enum Dispatch {
    One(Box<Runtime<B8821a1Ant>>),
    Two(Box<Runtime<B8821a2Ant>>),
}
macro_rules! apply {
    ($self:ident, $runtime:ident, $body:expr) => {
        match $self {
            Self::One($runtime) => $body,
            Self::Two($runtime) => $body,
        }
    };
}
impl Dispatch {
    pub fn due(&self, now: u64) -> bool {
        apply!(self, runtime, runtime.due(now))
    }
    pub fn new(raw_c3: u8) -> Self {
        if raw_c3 & 1 != 0 {
            Self::One(Box::new(Runtime::new(B8821a1Ant::default())))
        } else {
            Self::Two(Box::new(Runtime::new(B8821a2Ant::default())))
        }
    }
    pub fn lps_gate(&mut self) -> &mut LpsGate {
        apply!(self, runtime, &mut runtime.lps)
    }
    pub fn ampdu(&self) -> Option<AmpduCfg> {
        apply!(self, runtime, runtime.ampdu)
    }
    pub fn eapol(&mut self, btc: &mut BtCoexist, now: u64) {
        apply!(self, runtime, runtime.eapol(btc, now))
    }
    pub async fn notify<I: Io, M: BtMpSource>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        mp: &mut M,
        op: Notify<'_>,
    ) -> Result<(), Error> {
        apply!(
            self,
            runtime,
            runtime.notify(btc, mailbox, io, mp, op).await
        )
    }
    pub async fn watchdog<I: Io, M: BtMpSource>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        mp: &mut M,
        now: u64,
    ) -> Result<bool, Error> {
        apply!(
            self,
            runtime,
            runtime.watchdog(btc, mailbox, io, mp, now).await
        )
    }
    pub async fn lps<I: Io>(
        &mut self,
        btc: &mut BtCoexist,
        mailbox: &mut Mailbox,
        io: &I,
        enter: bool,
    ) -> Result<Option<[u8; 7]>, Error> {
        apply!(self, runtime, runtime.lps(btc, mailbox, io, enter).await)
    }
}
