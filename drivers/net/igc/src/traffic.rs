//! I225/I226 Qbv/Qav/launch-time programming, Linux igc_tsn.c.
use super::{hardware::Registers, igc::IgcError};
use narf_net::nic::{FlowRule, TrafficSchedule};
#[derive(Clone, Debug)]
pub(crate) struct Schedule {
    pub config: TrafficSchedule,
    pub base: u64,
    pub cycle: u32,
    pub windows: [(u32, u32); 4],
}
impl Schedule {
    pub fn validate(config: TrafficSchedule, queues: usize, now: u64) -> Result<Self, i32> {
        let mask = (1u8 << queues) - 1;
        if config.launch_time_queues & !mask != 0 || config.preemptible_queues & !mask != 0 {
            return Err(22);
        }
        let active = !config.gates.is_empty()
            || !config.shapers.is_empty()
            || config.launch_time_queues != 0
            || config.preemptible_queues != 0;
        let cycle = if config.cycle_ns == 0 && config.gates.is_empty() {
            1_000_000_000
        } else {
            config.cycle_ns
        };
        if active && (cycle == 0 || cycle > 1_000_000_000) {
            return Err(22);
        }
        let mut windows = [(0, cycle); 4];
        let mut cursor = 0u32;
        if !config.gates.is_empty() {
            windows = [(0, 0); 4];
            let mut closed = [false; 4];
            let mut opened = [false; 4];
            for gate in &config.gates {
                if gate.interval_ns == 0 || gate.mask & !mask != 0 {
                    return Err(22);
                }
                let end = cursor.checked_add(gate.interval_ns).ok_or(22)?;
                for q in 0..queues {
                    if gate.mask & (1 << q) != 0 {
                        if closed[q] {
                            return Err(95);
                        }
                        if !opened[q] {
                            windows[q].0 = cursor;
                            opened[q] = true;
                        }
                        windows[q].1 = end;
                    } else if opened[q] {
                        closed[q] = true;
                    }
                }
                cursor = end;
            }
            if cursor != cycle {
                return Err(22);
            }
            for q in 0..queues {
                if !opened[q] {
                    windows[q] = (cycle, cycle);
                }
            }
        }
        let mut shaped = 0;
        for s in &config.shapers {
            if s.queue > 1
                || usize::from(s.queue) >= queues
                || shaped & (1 << s.queue) != 0
                || s.idle_slope_kbps == 0
                || s.idle_slope_kbps > 2_500_000
                || s.high_credit < 0
                || s.high_credit > 65535
                || s.send_slope_kbps >= 0
                || s.low_credit > 0
            {
                return Err(22);
            }
            shaped |= 1 << s.queue;
        }
        let mut base = config.base_time_ns;
        if active && base <= now {
            base = base
                .checked_add(
                    ((now - base) / u64::from(cycle) + 1)
                        .checked_mul(u64::from(cycle))
                        .ok_or(22)?,
                )
                .ok_or(22)?;
        }
        if base / 1_000_000_000 > u64::from(u32::MAX) {
            return Err(22);
        }
        Ok(Self {
            config,
            base,
            cycle,
            windows,
        })
    }
    pub fn active(&self) -> bool {
        !self.config.gates.is_empty()
            || !self.config.shapers.is_empty()
            || self.config.launch_time_queues != 0
            || self.config.preemptible_queues != 0
    }
    pub fn apply(&self, r: &impl Registers, queues: usize, i226: bool) {
        if !self.active() {
            r.write(0x3570, 0);
            for q in 0..4 {
                r.write(0x3344 + q * 4, 0);
            }
            r.write(0x355c, 0x98);
            r.write(0x3310, 0);
            return;
        }
        adjust_offset(r);
        r.write(0x355c, 0x19);
        r.write(0x3404, 5 | (5 << 6) | (5 << 12) | (5 << 18) | (4 << 24));
        r.write(
            0x2404,
            (r.read(0x2404) & 0x80000000) | 15 | (2 << 6) | (15 << 12),
        );
        if i226 {
            r.write(0x41c, r.read(0x41c) | ((r.read(0x41c) & 15) << 8) | 0x1000);
        }
        for q in 0..queues {
            r.write(0x3324 + q as u64 * 4, self.windows[q].0);
            r.write(0x3334 + q as u64 * 4, self.windows[q].1);
            let mut control = if self.config.gates.is_empty() { 0 } else { 6 };
            if self.config.launch_time_queues & (1 << q) != 0 {
                control |= 1;
            }
            if q < 2 {
                if let Some(s) = self
                    .config
                    .shapers
                    .iter()
                    .find(|s| usize::from(s.queue) == q)
                {
                    let slope = (u64::from(s.idle_slope_kbps) * 61036).div_ceil(2_500_000) as u32;
                    r.write(0x3004 + q as u64 * 0x40, slope | 0x40000000);
                    r.write(
                        0x300c + q as u64 * 0x40,
                        0x80000000u32.wrapping_add(s.high_credit as u32 * 0x7736),
                    );
                    control |= if q == 0 { 0x80 } else { 0xc0 };
                } else {
                    r.write(0x3004 + q as u64 * 0x40, 0);
                    r.write(0x300c + q as u64 * 0x40, 0);
                }
            }
            r.write(0x3344 + q as u64 * 4, control);
        }
        let future = i226 && r.read(0x3318) == 0 && r.read(0x3314) == 0;
        r.write(0x3570, 9 | if future { 0x80 } else { 0 });
        r.write(0x3320, self.cycle);
        r.write(0x331c, self.cycle);
        r.write(0x3318, (self.base / 1_000_000_000) as u32);
        if future {
            r.write(0x3314, 0);
        }
        r.write(0x3314, (self.base % 1_000_000_000) as u32);
    }
    pub fn launch(&self, q: usize, time: u64, now: u64) -> Result<Launch, IgcError> {
        if self.config.launch_time_queues & (1 << q) == 0 || time < now || time < self.base {
            return Err(IgcError::Other("invalid launch time"));
        }
        let cycle = now.saturating_sub(self.base) / u64::from(self.cycle);
        let at = self.base + cycle * u64::from(self.cycle);
        let end = at + u64::from(self.cycle);
        if time >= end + u64::from(self.cycle) || (now >= at && end - now < 5000) {
            return Err(IgcError::Other("launch horizon"));
        }
        Ok(Launch {
            offset: ((time - at) % u64::from(self.cycle)) as u32,
            cycle,
            next: time >= end,
        })
    }
}

pub(crate) fn validate_flows(rules: &[FlowRule], queues: usize, unicast: usize) -> Result<(), i32> {
    let mut locations = alloc::collections::BTreeSet::new();
    let mut etypes = alloc::collections::BTreeSet::new();
    let mut macs = alloc::collections::BTreeSet::new();
    let mut prios = 0u8;
    for f in rules {
        if usize::from(f.queue) >= queues || !locations.insert(f.location) || f.location >= 32 {
            return Err(22);
        }
        if usize::from(f.ethertype.is_some())
            + usize::from(f.destination_mac.is_some())
            + usize::from(f.vlan_priority.is_some())
            != 1
        {
            return Err(95);
        }
        if let Some(t) = f.ethertype {
            if t < 0x600 || !etypes.insert(t) {
                return Err(22);
            }
        }
        if let Some(m) = f.destination_mac {
            if !super::hardware::valid_mac(m) || !macs.insert(m) {
                return Err(22);
            }
        }
        if let Some(p) = f.vlan_priority {
            if p > 7 || prios & (1 << p) != 0 {
                return Err(22);
            }
            prios |= 1 << p;
        }
    }
    if etypes.len() > 8 || (!macs.is_empty() && macs.len() + unicast > 15) {
        return Err(28);
    }
    Ok(())
}
pub(crate) fn flows(r: &impl Registers, rules: &[FlowRule], first_mac: usize) {
    for n in 0..8 {
        r.write(0x5cb0 + n * 4, 0);
    }
    r.write(0x55b0, 0);
    let mut et = 0;
    let mut mac = first_mac;
    let mut pq = 0;
    for f in rules {
        if let Some(t) = f.ethertype {
            r.write(
                0x5cb0 + et * 4,
                0x84000000 | (u32::from(f.queue) << 16) | u32::from(t),
            );
            et += 1;
        }
        if let Some(m) = f.destination_mac {
            r.write(
                0x5400 + mac as u64 * 8,
                u32::from_le_bytes(m[..4].try_into().unwrap()),
            );
            r.write(
                0x5404 + mac as u64 * 8,
                0x90000000
                    | (u32::from(f.queue) << 18)
                    | u32::from(u16::from_le_bytes(m[4..].try_into().unwrap())),
            );
            mac += 1;
        }
        if let Some(p) = f.vlan_priority {
            pq |= (8 | u32::from(f.queue)) << (p * 4);
        }
    }
    r.write(0x55b0, pq);
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Launch {
    pub offset: u32,
    pub cycle: u64,
    pub next: bool,
}

pub(crate) fn adjust_offset(r: &impl Registers) {
    let status = r.read(8);
    let offset = if status & 0x80 != 0 {
        if status & 0x400000 != 0 {
            0x578
        } else {
            0x12c
        }
    } else if status & 0x40 != 0 {
        0x578
    } else {
        0x34bc
    };
    r.write(0x3310, offset);
}
