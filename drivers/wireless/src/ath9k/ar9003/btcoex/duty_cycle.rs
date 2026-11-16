// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Live MCI weights: `gpio.c::ath_btcoex_{period,no_stomp}_timer` and
//! `mci.c::ath_mci_update_scheme` at the Linux revision in `btcoex.rs`.
//! The station worker supplies time and serializes service with reset,
//! calibration and packet DMA. Deadlines never own separate MMIO authority.
use super::super::mci;
use super::*;

#[derive(Default)]
pub(super) struct DutyCycle {
    running: bool,
    applied: Option<(u64, bool)>,
    period: Option<u64>,
    no_stomp: Option<u64>,
}

impl MciLink {
    /// `ath9k_btcoex_timer_pause`: cancel both deadlines before power or
    /// reset operations. The enclosing station lock excludes service.
    pub(in crate::ath9k) fn pause_duty_cycle(&mut self) {
        self.duty = DutyCycle::default();
    }

    /// `ath9k_btcoex_timer_resume`: discard the old no-stomp deadline
    /// and request an immediate period on the next worker service.
    pub(in crate::ath9k) fn resume_duty_cycle(&mut self) {
        self.pause_duty_cycle();
        self.duty.running = true;
    }

    /// Relative microseconds until work; no MMIO and no authority grant.
    pub(in crate::ath9k) fn duty_cycle_wait_us(&self, now: u64) -> Option<u64> {
        if !self.duty.running || !self.mci_enabled() || !self.btcoex.mci.ready {
            return None;
        }
        let mci = &self.btcoex.mci;
        if self.duty.applied != Some((mci.scheme_revision, mci.is_2g)) {
            return Some(0);
        }
        self.duty
            .period
            .into_iter()
            .chain(self.duty.no_stomp)
            .min()
            .map(|deadline| deadline.saturating_sub(now))
    }

    /// Apply a changed profile atomically with timer rearming, or service
    /// one due edge. Late service starts a fresh period; it never catches
    /// up in a loop or applies the previous period's stale no-stomp edge.
    pub(in crate::ath9k) fn service_duty_cycle(
        &mut self,
        io: &mut impl RegisterIo,
        now: u64,
    ) -> Result<(), BringUpError> {
        if self.duty_cycle_wait_us(now) != Some(0) {
            return Ok(());
        }
        if mci::state(io, &mut self.btcoex.mci, mci::MciState::Enable)? == 0 {
            self.pause_duty_cycle();
            return Err(BringUpError::DeviceGone);
        }
        let revision = (self.btcoex.mci.scheme_revision, self.btcoex.mci.is_2g);
        if self.duty.applied != Some(revision) {
            self.duty.period = None;
            self.duty.no_stomp = None;
            btcoex_disable(io, &mut self.btcoex)?;
            let priorities = self.btcoex.mci.profiles.concur_txprio;
            set_concur_txprio(&mut self.btcoex, priorities);
            self.duty.applied = Some(revision);
            if !self.btcoex.mci.is_2g {
                return Ok(());
            }
            self.duty.period = Some(now);
        }
        let profile = &self.btcoex.mci.profiles;
        let period = u64::from(profile.btcoex_period) * 1000;
        let no_stomp = u64::from(profile.btcoex_no_stomp) * 1000;
        let stomp = profile.bt_stomp_type;
        if period == 0 || no_stomp > period {
            self.pause_duty_cycle();
            return Err(BringUpError::BadState);
        }
        if self.duty.period.is_some_and(|due| now >= due) {
            bt_stomp(&mut self.btcoex, stomp);
            enable_mci(io, &mut self.btcoex)?;
            self.duty.period = Some(now.saturating_add(period));
            self.duty.no_stomp = (period != no_stomp).then(|| now.saturating_add(no_stomp));
        } else if self.duty.no_stomp.is_some_and(|due| now >= due) {
            match stomp {
                StompType::Low => bt_stomp(&mut self.btcoex, StompType::None),
                StompType::All => bt_stomp(&mut self.btcoex, StompType::Low),
                _ => {}
            }
            enable_mci(io, &mut self.btcoex)?;
            self.duty.no_stomp = None;
        }
        Ok(())
    }
}
