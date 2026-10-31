//! IEEE 802.3 MAC Merge software verification; Linux net/ethtool/mm.c.
use super::hardware::Registers;
use narf_net::nic::{Preemption, PreemptionStatus};
#[derive(Debug)]
pub(crate) struct Merge {
    pub config: Preemption,
    pub status: PreemptionStatus,
    link: bool,
    deadline: u64,
    awaiting: bool,
}
impl Merge {
    pub fn new() -> Self {
        Self {
            config: Preemption::default(),
            status: PreemptionStatus::default(),
            link: false,
            deadline: 0,
            awaiting: false,
        }
    }
    pub fn reset(&mut self) {
        self.status = PreemptionStatus::default();
        self.link = false;
        self.deadline = 0;
        self.awaiting = false;
    }
    /// Returns SMD-V/SMD-R requests. TX becomes active only after a response
    /// to a completed verify transmission, or explicit administrative override.
    pub fn tick(&mut self, now: u64, link: bool, events: u8) -> (bool, bool) {
        if self.link != link {
            self.reset();
            self.link = link;
        }
        if !self.config.enabled || !link {
            self.status.active = false;
            return (false, false);
        }
        let response = events & 1 != 0;
        if events & 4 != 0 && self.status.attempts != 0 {
            self.awaiting = true;
        }
        if events & 2 != 0 && self.awaiting {
            self.status.verified = true;
            self.status.active = true;
        }
        if !self.config.verify {
            self.status.active = self.config.tx_enabled;
        }
        self.status.active &= self.config.tx_enabled;
        if !self.config.tx_enabled
            || !self.config.verify
            || self.status.verified
            || self.status.failed
        {
            return (false, response);
        }
        if now >= self.deadline {
            if self.status.attempts >= 3 {
                self.status.failed = true;
                self.awaiting = false;
                return (false, response);
            }
            self.status.attempts += 1;
            self.awaiting = false;
            self.deadline = now + u64::from(self.config.verify_ms) * 1_000_000;
            return (true, response);
        }
        (false, response)
    }
    pub fn apply(&self, r: &impl Registers, queues: usize, preemptible: u8) {
        let enabled = self.config.enabled && self.link;
        let fragment = u32::from(self.config.minimum_fragment / 64 - 1);
        r.write(
            0x3570,
            (r.read(0x3570) & !(2 | 0xc000)) | if enabled { 2 | (fragment << 14) } else { 0 },
        );
        for q in 0..queues {
            let preempt = self.status.active && preemptible & (1 << q) != 0;
            let ctl = 0x3344 + q as u64 * 4;
            r.write(ctl, (r.read(ctl) & !8) | if preempt { 8 } else { 0 });
            let ctl = 0xe028 + q as u64 * 0x40;
            r.write(
                ctl,
                (r.read(ctl) & !(1 << 27))
                    | if self.status.active && !preempt {
                        1 << 27
                    } else {
                        0
                    },
            );
        }
    }
}
