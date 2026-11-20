// SPDX-License-Identifier: GPL-2.0-or-later
//! Desired setting, AP-notice and buffered-frame receipt owner. No hardware
//! success is inferred here: Radio supplies actual native TX+idle receipts.
use super::{
    tim::{Plan, Tim},
    Grant,
};
use crate::ath9k::packet::Error;
use alloc::sync::Arc;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) enum Action {
    Null(u64, bool),
    Poll(u64),
}
struct Pending {
    ticket: u64,
    enabled: Option<bool>,
    epoch: u64,
    deadline: u64,
}
pub(in crate::ath9k) struct Owner {
    pub grant: Arc<Grant>,
    desired: bool,
    announced: Option<bool>,
    serial: u64,
    epoch: u64,
    tim: Option<Tim>,
    pending: Option<Pending>,
    beacon_wait: bool,
    poll_wait: Option<u64>,
    poll_data: Option<bool>,
    need_poll: bool,
    cab: bool,
    polls: u8,
}
impl Owner {
    pub fn new(grant: Arc<Grant>, epoch: u64) -> Self {
        Self {
            grant,
            desired: false,
            announced: Some(false),
            serial: 0,
            epoch,
            tim: None,
            pending: None,
            beacon_wait: false,
            poll_wait: None,
            poll_data: None,
            need_poll: false,
            cab: false,
            polls: 0,
        }
    }
    pub fn desired(&self) -> bool {
        self.desired
    }
    pub fn set(&mut self, desired: bool) -> Result<(), Error> {
        self.grant.check()?;
        self.desired = desired;
        Ok(())
    }
    pub fn mark_pm(&self) -> bool {
        self.announced != Some(false)
    }
    pub fn data_ready(&self) -> bool {
        self.pending.is_none() && self.announced == Some(self.desired)
    }
    pub fn active(&self) -> bool {
        self.desired || self.announced != Some(false) || self.pending.is_some()
    }
    pub fn key_epoch(&mut self, epoch: u64) {
        if epoch == self.epoch {
            return;
        }
        self.epoch = epoch;
        // A published old notice may still change the AP's state. Its real
        // DMA remains retained; after receipt require a new current notice.
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.enabled.is_some())
        {
            self.announced = None;
        }
        self.poll_wait = None;
        self.poll_data = None;
        self.need_poll = false;
        self.cab = false;
    }
    pub fn beacon(&mut self, tim: Tim, tsf: u64) -> Option<Plan> {
        if !self.active() {
            return None;
        }
        if self.tim.is_some_and(|old| old.timestamp == tim.timestamp) {
            return None;
        }
        self.tim = Some(tim);
        self.beacon_wait = false;
        self.polls = 0;
        self.need_poll = tim.unicast;
        self.cab = tim.cab;
        if tim.cab {
            self.beacon_wait = true;
        }
        Some(tim.plan(tsf))
    }
    pub fn wake_beacon(&mut self) {
        if self.active() {
            self.beacon_wait = true;
        }
    }
    pub fn resync(&mut self) {
        self.tim = None;
        self.beacon_wait = true;
    }
    pub fn accepted_data(&mut self, unicast: bool, more_data: bool, more_fragments: bool) {
        if !self.active() {
            return;
        }
        if unicast
            && !more_fragments
            && (self.poll_wait.is_some()
                || self
                    .pending
                    .as_ref()
                    .is_some_and(|pending| pending.enabled.is_none()))
        {
            self.poll_data = Some(more_data);
            if self.pending.is_none() {
                self.poll_wait = None;
                self.need_poll = more_data;
            }
        } else if !unicast && !more_data {
            self.cab = false;
            self.beacon_wait = false;
        }
    }
    pub fn tick(&self, now: u64) -> Result<(), Error> {
        self.grant.check()?;
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| now >= pending.deadline)
            || self.poll_wait.is_some_and(|deadline| now >= deadline)
        {
            return Err(Error::Timeout);
        }
        Ok(())
    }
    pub fn next(&mut self, now: u64, epoch: u64) -> Result<Option<Action>, Error> {
        self.tick(now)?;
        self.key_epoch(epoch);
        if self.pending.is_some() {
            return Ok(None);
        }
        let enabled = if self.announced != Some(self.desired) {
            if self.desired && self.tim.is_none() {
                return Ok(None);
            }
            Some(Some(self.desired))
        } else if self.desired && self.need_poll && self.poll_wait.is_none() && self.polls < 8 {
            Some(None)
        } else {
            None
        };
        let Some(enabled) = enabled else {
            return Ok(None);
        };
        self.serial = self.serial.checked_add(1).ok_or(Error::State)?;
        self.pending = Some(Pending {
            ticket: self.serial,
            enabled,
            epoch,
            deadline: now.checked_add(100_000_000).ok_or(Error::Timeout)?,
        });
        if enabled.is_none() {
            self.polls += 1;
            self.poll_data = None;
        }
        Ok(Some(match enabled {
            Some(on) => Action::Null(self.serial, on),
            None => Action::Poll(self.serial),
        }))
    }
    /// Caller proves exact successful original native TX receipt, QCU idle
    /// and a fresh real RX-idle fence after every queued key/peer update.
    /// Returns Some(false) only for an actual completed awake notice.
    pub fn delivered(&mut self, ticket: u64, now: u64, epoch: u64) -> Result<Option<bool>, Error> {
        let pending = self.pending.take().ok_or(Error::State)?;
        if pending.ticket != ticket {
            return Err(Error::State);
        }
        if pending.epoch != epoch {
            if pending.enabled.is_some() {
                self.announced = None;
            }
            return Ok(None);
        }
        if let Some(enabled) = pending.enabled {
            self.announced = Some(enabled);
            if !enabled {
                // Off disarms the actual timers. A later enable must wait
                // for a fresh current beacon and reprogram those timers,
                // rather than reuse stale TIM facts from the prior doze.
                self.tim = None;
                self.poll_wait = None;
                self.poll_data = None;
                self.need_poll = false;
                self.beacon_wait = false;
                self.cab = false;
            }
            return Ok(Some(enabled));
        }
        if let Some(more) = self.poll_data.take() {
            self.need_poll = more;
        } else {
            self.poll_wait = Some(now.checked_add(1_048_576_000).ok_or(Error::Timeout)?);
        }
        Ok(None)
    }
    pub fn quiet(&self) -> bool {
        self.desired
            && self.announced == Some(true)
            && self.tim.is_some()
            && self.pending.is_none()
            && !self.beacon_wait
            && self.poll_wait.is_none()
            && !self.need_poll
            && !self.cab
    }
}
