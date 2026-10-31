//! I225/I226 adjustable clock and packet timestamps. Linux igc_ptp.c.
use super::{hardware::Registers, igc::IgcError};
use alloc::collections::VecDeque;
use narf_net::nic::{Timestamp, TimestampConfig};

#[derive(Debug)]
pub(crate) struct ClockState {
    pub config: TimestampConfig,
    pub ppb: i32,
    pub saved: Option<(u64, u64)>,
    pub pending: [Option<(u64, u64)>; 4],
    pub events: VecDeque<Timestamp>,
    pub timeouts: u64,
    pub quarantined: u8,
}
impl ClockState {
    pub fn new() -> Self {
        Self {
            config: Default::default(),
            ppb: 0,
            saved: None,
            pending: [None; 4],
            events: VecDeque::new(),
            timeouts: 0,
            quarantined: 0,
        }
    }
    pub fn reserve(&mut self, queue: usize, cookie: u64, now: u64) -> Result<u32, IgcError> {
        if !self.config.tx {
            return Err(IgcError::Other("TX timestamping disabled"));
        }
        if self.events.len() >= 252 {
            return Err(IgcError::Other("timestamp event queue full"));
        }
        if self.pending[queue].is_some() || self.quarantined & (1 << queue) != 0 {
            return Err(IgcError::Other("TX timestamp register busy"));
        }
        self.pending[queue] = Some((cookie, now));
        Ok(0x00080000 | ((queue as u32) << 16))
    }
    pub fn cancel(&mut self, error: i32) {
        for (q, pending) in self.pending.iter_mut().enumerate() {
            if let Some((cookie, _)) = pending.take() {
                self.quarantined |= 1 << q;
                self.events.push_back(Timestamp {
                    cookie,
                    nanoseconds: 0,
                    transmit: true,
                    error: Some(error),
                });
            }
        }
    }
    pub fn collect(&mut self, r: &impl Registers, now: u64) {
        let valid = r.read(0xb614);
        for q in 0..4 {
            if let Some((cookie, start)) = self.pending[q] {
                if valid & (1 << q) != 0 {
                    let reg = [0xb618, 0xb698, 0xb6b8, 0xb6d8][q];
                    let ns = u64::from(r.read(reg));
                    let sec = u64::from(r.read(reg + 4));
                    if self.events.len() < 256 {
                        self.events.push_back(Timestamp {
                            cookie,
                            nanoseconds: (sec * 1_000_000_000 + ns)
                                .saturating_add(tx_latency(r.read(8))),
                            transmit: true,
                            error: (ns >= 1_000_000_000).then_some(5),
                        });
                    }
                    self.pending[q] = None;
                } else if now.saturating_sub(start) > 1_000_000_000 {
                    self.pending[q] = None;
                    if self.events.len() < 256 {
                        self.events.push_back(Timestamp {
                            cookie,
                            nanoseconds: 0,
                            transmit: true,
                            error: Some(110),
                        });
                    }
                    self.timeouts += 1;
                    self.quarantined |= 1 << q;
                }
            } else if valid & (1 << q) != 0 {
                // A late timestamp terminates the old request. Clear it before
                // allowing a new packet to claim this register.
                let reg = [0xb618, 0xb698, 0xb6b8, 0xb6d8][q];
                let _ = r.read(reg + 4);
                self.quarantined &= !(1 << q);
            }
        }
    }
}

pub(crate) fn read(r: &impl Registers) -> Result<u64, IgcError> {
    let ns = r.read(0xb600);
    let sec = r.read(0xb604); // low read latches high
    if ns >= 1_000_000_000 {
        return Err(IgcError::Other("clock unavailable"));
    }
    Ok(u64::from(sec) * 1_000_000_000 + u64::from(ns))
}
pub(crate) fn write(r: &impl Registers, ns: u64) -> Result<(), IgcError> {
    if ns / 1_000_000_000 > u64::from(u32::MAX) {
        return Err(IgcError::Other("clock range"));
    }
    r.write(0xb600, (ns % 1_000_000_000) as u32);
    r.write(0xb604, (ns / 1_000_000_000) as u32);
    r.flush();
    Ok(())
}
pub(crate) fn frequency(r: &impl Registers, ppb: i32) -> Result<(), IgcError> {
    if ppb.unsigned_abs() > 62_499_999 {
        return Err(IgcError::Other("clock frequency range"));
    }
    let rate = (u64::from(ppb.unsigned_abs()) * 1_073_741_824 / 78_125_000) as u32;
    r.write(0xb608, rate | if ppb < 0 { 0x80000000 } else { 0 });
    Ok(())
}
pub(crate) fn configure(r: &impl Registers, queues: usize, c: TimestampConfig) {
    r.write(0xb60c, r.read(0xb60c) | 0x40000000);
    r.write(0xb640, 0);
    r.write(0xb614, if c.tx { 0x30 } else { 0 });
    r.write(0xb620, if c.rx { 0x418 } else { 0 });
    r.write(
        0x2404,
        (r.read(0x2404) & !(1 << 31)) | if c.rx { 1 << 31 } else { 0 },
    );
    for q in 0..queues {
        let reg = 0xc00c + q as u64 * 0x40;
        r.write(
            reg,
            (r.read(reg) & !(0x40000000 | (3 << 14) | (3 << 17)))
                | if c.rx { 0x40004000 } else { 0 },
        );
    }
}

pub(crate) fn rx_latency(status: u32) -> u64 {
    if status & 0x80 != 0 {
        if status & 0x400000 != 0 {
            1485
        } else {
            300
        }
    } else if status & 0x40 != 0 {
        185
    } else {
        6450
    }
}
fn tx_latency(status: u32) -> u64 {
    if status & 0x80 != 0 {
        if status & 0x400000 != 0 {
            1325
        } else {
            80
        }
    } else if status & 0x40 != 0 {
        58
    } else {
        240
    }
}

pub(crate) fn advance(clock: u64, elapsed: u64, ppb: i32) -> u64 {
    let delta = i128::from(elapsed) + i128::from(elapsed) * i128::from(ppb) / 1_000_000_000;
    u64::try_from(i128::from(clock) + delta).unwrap_or(u64::MAX)
}
