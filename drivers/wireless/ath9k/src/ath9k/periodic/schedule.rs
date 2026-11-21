// SPDX-License-Identifier: GPL-2.0-or-later
//! link.c station deadlines. No timer or setter fabricates a hardware receipt.
use super::Error;
const SHORT: u64 = 1_000;
const LONG: u64 = 30_000;
const RESTART: u64 = 1_200_000; // actual ath9k.h:20 minutes, not180 seconds.
const ANI: u64 = 1_000;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Due {
    pub short: bool,
    pub long: bool,
    pub ani: bool,
    pub restart: bool,
    pub need_wake: bool,
}
pub(in crate::ath9k) struct Schedule {
    last_seen: u64,
    short: u64,
    long: u64,
    ani: u64,
    valid: u64,
    sleep_tick: u64,
    skips: u8,
}
impl Schedule {
    /// The accepted actual initial correction seeds valid=true; caller
    /// retains the actual short-list owner when calibrations need restarting.
    pub fn new(now: u64) -> Self {
        Self {
            last_seen: now,
            short: now,
            long: now,
            ani: now,
            valid: now,
            sleep_tick: now,
            skips: 0,
        }
    }
    pub fn due(
        &mut self,
        now: u64,
        awake: bool,
        caldone: bool,
        interference: bool,
    ) -> Result<Due, Error> {
        if now < self.last_seen {
            return Err(Error::State);
        }
        self.last_seen = now;
        if !awake {
            // Source ANI_MAX_SKIP_COUNT10 does not silently access a sleeping
            // radio. A separate current clock owner must complete any wake.
            if now.saturating_sub(self.sleep_tick) >= ANI {
                self.skips = self.skips.saturating_add(1);
                self.sleep_tick = now;
            }
            return Ok(Due {
                need_wake: self.skips >= 10,
                ..Due::default()
            });
        }
        self.skips = 0;
        Ok(Due {
            short: !caldone && now.saturating_sub(self.short) >= SHORT,
            long: now.saturating_sub(self.long) >= if interference { SHORT } else { LONG },
            ani: now.saturating_sub(self.ani) >= ANI,
            restart: caldone && now.saturating_sub(self.valid) >= RESTART,
            need_wake: false,
        })
    }
    /// Call only for operations the retained current owner actually started,
    /// not for scheduler intent refused by live RX/TX/control/key ownership.
    pub fn started(&mut self, now: u64, actual: Due) -> Result<(), Error> {
        if now < self.last_seen || actual.need_wake {
            return Err(Error::State);
        }
        self.last_seen = now;
        if actual.short {
            self.short = now;
            self.valid = now;
        }
        if actual.long {
            self.long = now;
        }
        if actual.ani {
            self.ani = now;
        }
        if actual.restart {
            self.valid = now;
        }
        Ok(())
    }
}
