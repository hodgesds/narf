// SPDX-License-Identifier: GPL-2.0-or-later
//! Generic TSF timers for the AR9003 generation: the `hw.c` generic-timer
//! table (`ath_gen_timer_table`, `ath_gen_timer_alloc/start/stop/free`,
//! `ath_gen_timer_isr`, `ath9k_hw_gen_timer_start_tsf2`) and the
//! `gen_tmr_configuration` register map (Linux @ `cbbddb6`,
//! `drivers/net/wireless/ath/ath9k/`).
//!
//! The table is the TSF2 owner the WoW layer reports about:
//! `wow::Wakeup::tsf2_restart` says the WoW-sleep path found
//! `AR_DC_TSF2_ENABLE` clear, and `wow_resume` restarts TSF2 through
//! `GenTimerTable::start_tsf2` only when this table says a TSF2 timer
//! (index 8..15) was allocated. Linux restarts TSF2 the same way, in
//! `ath9k_hw_init` after the resume reset (`hw.c:2045` calls
//! `ath9k_hw_gen_timer_start_tsf2`, which is a no-op unless
//! `timer_table->tsf2_enabled`).
//!
//! Shape notes, all deliberate divergences from Linux:
//! * `GenTimer` carries the interrupt-arm flags (`trigger`, `overflow`)
//!   instead of Linux's `trigger`/`overflow` callbacks plus `arg`: no
//!   in-tree consumer registers a callback yet, so the table cannot
//!   invoke one. `start` arms the `AR_IMR_S5` bits exactly when the
//!   flags say so, and `isr` returns the fired sets
//!   (`GenTimerEvents`) instead of calling into a consumer — the
//!   tree's event-struct idiom, cf. `ar9003::irq::Events`. The first
//!   consumer wires the S5 dispatch (the `ar9003::irq` layer already
//!   reports `gen_timer`) and the callback shape then.
//! * `alloc` refuses a double-alloc with `BadState`; Linux overwrites
//!   the slot silently. A second alloc of a live timer is a caller bug
//!   here, not a silent leak.
//! * `start`/`stop` program the per-timer `AR_IMR_S5` bits but do not
//!   touch `ah->imask` / `ATH9K_INT_GENTIMER`: the interrupt mask is
//!   owned by `ar9003::irq` and the owner, which enable the GENTIMER
//!   interrupt when the first timer starts and may drop it when
//!   `timer_mask()` reaches zero. `stop` documents the same boundary.
//! * `tsf2_enabled` is sticky, as in Linux: neither `stop` nor `free`
//!   clears it. A TSF2 timer allocated once means TSF2 was enabled.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::{rmw, Revision};
use crate::ath9k::identity::{BringUpError, RegisterIo};

/// `hw.h:538`: `ATH_MAX_GEN_TIMER`.
pub(in crate::ath9k) const MAX_GEN_TIMER: usize = 16;
/// `reg.h:1966`: `AR_FIRST_NDP_TIMER` — the first generic-timer index;
/// indices below it are the fixed-function beacon timers, not allocatable.
pub(in crate::ath9k) const FIRST_NDP_TIMER: u8 = 7;
/// `reg.h:1965`: `AR_GEN_TIMER_BANK_1_LEN` — timers 0..7 use TSF,
/// timers 8..15 use TSF2.
const GEN_TIMER_BANK_1_LEN: u8 = 8;

/// `reg.h:1668`: `AR_RESET_TSF`.
const AR_RESET_TSF: u64 = 0x8020;
/// `reg.h:1670`: `AR_RESET_TSF2_ONCE`.
const AR_RESET_TSF2_ONCE: u32 = 0x0200_0000;
/// `reg.h:2063`: `AR_DIRECT_CONNECT` (also in `wow.rs`: the WoW layer
/// reads the same register for `AR_DC_TSF2_ENABLE`).
const AR_DIRECT_CONNECT: u64 = 0x83a0;
/// `reg.h:2064`: `AR_DC_AP_STA_EN` — bit 0 of `AR_DIRECT_CONNECT`, the
/// same bit `wow.rs` names `AR_DC_TSF2_ENABLE` on the read side.
const AR_DC_AP_STA_EN: u32 = 0x0000_0001;
/// `reg.h`: `AR_MAC_PCU_GEN_TIMER_TSF_SEL` (also in `wow.rs`: the WoW
/// sleep path reads it to decide whether a TSF2 timer is armed).
const AR_MAC_PCU_GEN_TIMER_TSF_SEL: u64 = 0x83d8;
/// `reg.h:254`: `AR_IMR_S5` (also in `ath9k::irq`: the S5 mask register).
const AR_IMR_S5: u64 = 0x00b8;
/// `reg.h:261`: `AR_IMR_S5_GENTIMER_TRIG`.
const AR_IMR_S5_GENTIMER_TRIG: u32 = 0x0000_FF80;
/// `reg.h:262`: `AR_IMR_S5_GENTIMER_TRIG_S`.
const AR_IMR_S5_GENTIMER_TRIG_S: u32 = 0;
/// `reg.h:263`: `AR_IMR_S5_GENTIMER_THRESH`.
const AR_IMR_S5_GENTIMER_THRESH: u32 = 0xFF80_0000;
/// `reg.h:264`: `AR_IMR_S5_GENTIMER_THRESH_S`.
const AR_IMR_S5_GENTIMER_THRESH_S: u32 = 16;
/// `reg.h:257`: `AR_ISR_S5_GENTIMER_TRIG`.
const AR_ISR_S5_GENTIMER_TRIG: u32 = 0x0000_FF80;
/// `reg.h:258`: `AR_ISR_S5_GENTIMER_TRIG_S`.
const AR_ISR_S5_GENTIMER_TRIG_S: u32 = 0;
/// `reg.h:259`: `AR_ISR_S5_GENTIMER_THRESH`.
const AR_ISR_S5_GENTIMER_THRESH: u32 = 0xFF80_0000;
/// `reg.h:260`: `AR_ISR_S5_GENTIMER_THRESH_S`.
const AR_ISR_S5_GENTIMER_THRESH_S: u32 = 16;

/// `reg.h:1971`: `AR_GEN_TIMERS(i)` is `0x8200 + (i << 2)`, so
/// `AR_NEXT_NDP_TIMER` (`reg.h:1980`, `AR_GEN_TIMERS(7)`) is `0x821c`.
const AR_NEXT_NDP_TIMER: u64 = 0x821c;
/// `reg.h:1989`: `AR_NDP_PERIOD` (`AR_GEN_TIMERS(15)`) is `0x823c`.
const AR_NDP_PERIOD: u64 = 0x823c;
/// `reg.h:1991`: `AR_TIMER_MODE` is `0x8240`.
const AR_TIMER_MODE: u64 = 0x8240;
/// `reg.h:1964`: `AR_NEXT_NDP2_TIMER` is `0x8180`.
const AR_NEXT_NDP2_TIMER: u64 = 0x8180;
/// `reg.h:1967`: `AR_NDP2_PERIOD` is `0x81a0`.
const AR_NDP2_PERIOD: u64 = 0x81a0;
/// `reg.h:1968`: `AR_NDP2_TIMER_MODE` is `0x81c0` (also in `wow.rs`:
/// the WoW sleep path reads it for the AR9485 TSF2 check).
const AR_NDP2_TIMER_MODE: u64 = 0x81c0;

/// `hw.h:122`: `SM(_v, _f)` is `((_v) << _f##_S) & _f`.
const fn sm(value: u32, field: u32, shift: u32) -> u32 {
    (value << shift) & field
}

/// `hw.h:123`: `MS(_v, _f)` is `((_v) & _f) >> _f##_S`.
const fn ms(value: u32, field: u32, shift: u32) -> u32 {
    (value & field) >> shift
}

/// `hw.h:542`: `struct ath_gen_timer_configuration` — the register
/// addresses and mode bit for one generic-timer slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct GenTimerConfig {
    pub next_addr: u64,
    pub period_addr: u64,
    pub mode_addr: u64,
    pub mode_mask: u32,
}

/// `hw.c:3072`: `gen_tmr_configuration`. Timers 0..7 share the NDP
/// registers (`AR_NEXT_NDP_TIMER`, `AR_NDP_PERIOD`, `AR_TIMER_MODE`,
/// mode mask `0x0080`); timers 8..15 step the NDP2 registers by 4 per
/// slot with mode mask `0x0001 << (index - 8)`. Computed, not
/// transcribed: the test holds the literal Linux table.
pub(in crate::ath9k) const fn config(index: u8) -> GenTimerConfig {
    if index < GEN_TIMER_BANK_1_LEN {
        GenTimerConfig {
            next_addr: AR_NEXT_NDP_TIMER,
            period_addr: AR_NDP_PERIOD,
            mode_addr: AR_TIMER_MODE,
            mode_mask: 0x0080,
        }
    } else {
        let bank2 = (index - GEN_TIMER_BANK_1_LEN) as u64;
        GenTimerConfig {
            next_addr: AR_NEXT_NDP2_TIMER + (bank2 << 2),
            period_addr: AR_NDP2_PERIOD + (bank2 << 2),
            mode_addr: AR_NDP2_TIMER_MODE,
            mode_mask: 0x0001 << (index - GEN_TIMER_BANK_1_LEN),
        }
    }
}

/// `hw.h:549`: `struct ath_gen_timer` — one allocated slot. Linux
/// holds `trigger`/`overflow` callbacks plus `arg`; this tree holds
/// the arm flags instead (see the module docs): no in-tree consumer
/// registers a callback yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct GenTimer {
    pub index: u8,
    /// `start` arms the trigger interrupt (`AR_IMR_S5_GENTIMER_TRIG`).
    pub trigger: bool,
    /// `start` arms the threshold interrupt (`AR_IMR_S5_GENTIMER_THRESH`).
    pub overflow: bool,
}

/// `hw.c:3249`: `ath_gen_timer_isr`'s report. Linux calls the fired
/// timer's `overflow`/`trigger` callback inline; this tree returns the
/// fired sets and lets the caller dispatch (bit `i` = timer `i`).
/// A timer whose threshold fired does not also report a trigger, as in
/// Linux (the threshold loop clears the trigger bit first).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct GenTimerEvents {
    pub trigger: u16,
    pub overflow: u16,
}

/// `hw.h:556`: `struct ath_gen_timer_table` — the sixteen slots, the
/// running-timer mask, and the sticky TSF2 fact. Held by the owner
/// (`ah->hw_gen_timers`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct GenTimerTable {
    timers: [Option<GenTimer>; MAX_GEN_TIMER],
    timer_mask: u16,
    tsf2_enabled: bool,
}

impl GenTimerTable {
    /// `timer_table->tsf2_enabled`: a TSF2 timer (index 8..15) was
    /// allocated at least once. Sticky — `stop`/`free` never clear it.
    pub(in crate::ath9k) fn tsf2_enabled(&self) -> bool {
        self.tsf2_enabled
    }

    /// `timer_table->timer_mask`: bit `i` set while timer `i` runs.
    pub(in crate::ath9k) fn timer_mask(&self) -> u16 {
        self.timer_mask
    }

    /// The allocated timer at `index`, if any.
    pub(in crate::ath9k) fn timer(&self, index: u8) -> Option<GenTimer> {
        if usize::from(index) < MAX_GEN_TIMER {
            self.timers[usize::from(index)]
        } else {
            None
        }
    }

    /// `hw.c:3117`: `ath_gen_timer_alloc`. Index must be a generic
    /// timer (`AR_FIRST_NDP_TIMER`..`ATH_MAX_GEN_TIMER`); a TSF2
    /// timer additionally needs `AR_SREV_9300_20_OR_LATER` (every
    /// modeled chip satisfies it — the gate stays literal for future
    /// chips). The first TSF2 alloc sets `tsf2_enabled` and restarts
    /// TSF2, as Linux does. On a restart I/O failure the table is
    /// left unallocated.
    pub(in crate::ath9k) fn alloc(
        &mut self,
        io: &mut impl RegisterIo,
        revision: &Revision,
        index: u8,
        trigger: bool,
        overflow: bool,
    ) -> Result<GenTimer, BringUpError> {
        if index < FIRST_NDP_TIMER || usize::from(index) >= MAX_GEN_TIMER {
            return Err(BringUpError::BadState);
        }
        if index > FIRST_NDP_TIMER && !revision.ar9300_20_or_later() {
            return Err(BringUpError::BadState);
        }
        if self.timers[usize::from(index)].is_some() {
            return Err(BringUpError::BadState);
        }
        if index > FIRST_NDP_TIMER && !self.tsf2_enabled {
            self.tsf2_enabled = true;
            if let Err(error) = self.start_tsf2(io) {
                self.tsf2_enabled = false;
                return Err(error);
            }
        }
        let timer = GenTimer {
            index,
            trigger,
            overflow,
        };
        self.timers[usize::from(index)] = Some(timer);
        Ok(timer)
    }

    /// `hw.c:3107`: `ath9k_hw_gen_timer_start_tsf2` — when a TSF2
    /// timer was enabled, set `AR_DC_AP_STA_EN` and reset TSF2 once.
    /// A no-op otherwise. `wow_resume` calls this when `wakeup`
    /// reports `tsf2_restart`.
    pub(in crate::ath9k) fn start_tsf2(
        &self,
        io: &mut impl RegisterIo,
    ) -> Result<(), BringUpError> {
        if self.tsf2_enabled {
            rmw(io, AR_DIRECT_CONNECT, 0, AR_DC_AP_STA_EN)?;
            rmw(io, AR_RESET_TSF, 0, AR_RESET_TSF2_ONCE)?;
        }
        Ok(())
    }

    /// `hw.c:3154`: `ath9k_hw_gen_timer_start` — program the timer's
    /// next/period registers, set its mode bit, select TSF or TSF2
    /// for AR9462/AR9565 (bank 1 uses TSF, bank 2 uses TSF2), and arm
    /// the trigger/threshold `AR_IMR_S5` bits the timer asked for.
    /// The `ATH9K_INT_GENTIMER` interrupt enable itself is the
    /// interrupt-mask owner's (see the module docs), not this table's.
    /// Refuses a timer this table never allocated.
    pub(in crate::ath9k) fn start(
        &mut self,
        io: &mut impl RegisterIo,
        revision: &Revision,
        timer: &GenTimer,
        next: u32,
        period: u32,
    ) -> Result<(), BringUpError> {
        if self.timer(timer.index) != Some(*timer) {
            return Err(BringUpError::BadState);
        }
        let cfg = config(timer.index);
        self.timer_mask |= 1u16 << timer.index;
        io.write32(cfg.next_addr, next);
        io.write32(cfg.period_addr, period);
        rmw(io, cfg.mode_addr, 0, cfg.mode_mask)?;
        if revision.ar9462() || revision.ar9565() {
            if timer.index < GEN_TIMER_BANK_1_LEN {
                rmw(io, AR_MAC_PCU_GEN_TIMER_TSF_SEL, 1u32 << timer.index, 0)?;
            } else {
                rmw(io, AR_MAC_PCU_GEN_TIMER_TSF_SEL, 0, 1u32 << timer.index)?;
            }
        }
        let mut mask = 0;
        if timer.trigger {
            mask |= sm(
                1u32 << timer.index,
                AR_IMR_S5_GENTIMER_TRIG,
                AR_IMR_S5_GENTIMER_TRIG_S,
            );
        }
        if timer.overflow {
            mask |= sm(
                1u32 << timer.index,
                AR_IMR_S5_GENTIMER_THRESH,
                AR_IMR_S5_GENTIMER_THRESH_S,
            );
        }
        if mask != 0 {
            rmw(io, AR_IMR_S5, 0, mask)?;
        }
        Ok(())
    }

    /// `hw.c:3204`: `ath9k_hw_gen_timer_stop` — clear the timer's
    /// mode bit, switch a bank-2 timer back to TSF on AR9462/AR9565,
    /// and clear both `AR_IMR_S5` bits. The slot stays allocated
    /// (only `free` releases it) and `tsf2_enabled` stays set. When
    /// `timer_mask()` reaches zero the interrupt-mask owner may drop
    /// `ATH9K_INT_GENTIMER`; this table does not touch `ah->imask`.
    /// Refuses a timer this table never allocated.
    pub(in crate::ath9k) fn stop(
        &mut self,
        io: &mut impl RegisterIo,
        revision: &Revision,
        timer: &GenTimer,
    ) -> Result<(), BringUpError> {
        if self.timer(timer.index) != Some(*timer) {
            return Err(BringUpError::BadState);
        }
        let cfg = config(timer.index);
        rmw(io, cfg.mode_addr, cfg.mode_mask, 0)?;
        if (revision.ar9462() || revision.ar9565()) && timer.index >= GEN_TIMER_BANK_1_LEN {
            rmw(io, AR_MAC_PCU_GEN_TIMER_TSF_SEL, 1u32 << timer.index, 0)?;
        }
        let mask = sm(
            1u32 << timer.index,
            AR_IMR_S5_GENTIMER_TRIG,
            AR_IMR_S5_GENTIMER_TRIG_S,
        ) | sm(
            1u32 << timer.index,
            AR_IMR_S5_GENTIMER_THRESH,
            AR_IMR_S5_GENTIMER_THRESH_S,
        );
        rmw(io, AR_IMR_S5, mask, 0)?;
        self.timer_mask &= !(1u16 << timer.index);
        Ok(())
    }

    /// `hw.c:3236`: `ath_gen_timer_free` — release the hardware slot.
    /// Linux leaves `tsf2_enabled` and the mask bit alone (the mask
    /// bit is `stop`'s); this also only clears the slot when it still
    /// holds this exact timer, so freeing a stale copy cannot release
    /// a timer re-allocated at the same index.
    pub(in crate::ath9k) fn free(&mut self, timer: GenTimer) {
        if self.timer(timer.index) == Some(timer) {
            self.timers[usize::from(timer.index)] = None;
        }
    }

    /// `hw.c:3249`: `ath_gen_timer_isr` — which allocated timers the
    /// S5 interrupt reports. `s5_trigger`/`s5_thresh` are the raw
    /// `AR_ISR_S5` words `ar9003_mac.c::ar9003_hw_get_isr` reads; the
    /// `MS` extraction (`AR_ISR_S5_GENTIMER_TRIG_S` 0,
    /// `AR_ISR_S5_GENTIMER_THRESH_S` 16) puts bit `i` on timer `i`.
    /// Only timers in `timer_mask` (running) report.
    pub(in crate::ath9k) fn isr(&self, s5_trigger: u32, s5_thresh: u32) -> GenTimerEvents {
        let trigger = ms(
            s5_trigger,
            AR_ISR_S5_GENTIMER_TRIG,
            AR_ISR_S5_GENTIMER_TRIG_S,
        ) & u32::from(self.timer_mask);
        let thresh = ms(
            s5_thresh,
            AR_ISR_S5_GENTIMER_THRESH,
            AR_ISR_S5_GENTIMER_THRESH_S,
        ) & u32::from(self.timer_mask);
        GenTimerEvents {
            trigger: (trigger & !thresh) as u16,
            overflow: thresh as u16,
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests;
