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
    pub fn apply(&self, r: &impl Registers, queues: usize, i226: bool, reverse_txq_prio: bool) {
        if !self.active() {
            r.write(0x3570, 0);
            for q in 0..4 {
                r.write(0x3344 + q * 4, 0);
            }
            r.write(0x355c, 0x98);
            r.write(0x3310, 0);
            // Linux igc_tsn_disable restores the default TX arbitration
            // (queue 0 highest priority).
            write_txarb(r, false);
            return;
        }
        // Linux igc_tsn_enable reverses TX arbitration when the
        // reverse-tsn-txq-prio private flag is set (or strict priority is
        // enabled; NARF has no strict-priority marker yet, so only the flag
        // reverses here).
        if reverse_txq_prio {
            write_txarb(r, true);
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

/// TX arbitration priority fields (Linux `igc_tsn_tx_arb`, IGC_TXARB
/// 0x3354): the four 2-bit queue-priority fields occupy the low byte;
/// reversed is 0x1B (queue 3 highest), normal is 0xE4 (queue 0 highest).
/// Read-modify-write preserves the other TXARB bits.
fn write_txarb(r: &impl Registers, reverse: bool) {
    let txarb = (r.read(0x3354) & !0xff) | if reverse { 0x1b } else { 0xe4 };
    r.write(0x3354, txarb);
}

/// Match-field count for one rule. The default-queue rule is not
/// counted here: it has no match field by construction.
fn criteria(f: &FlowRule) -> usize {
    usize::from(f.ethertype.is_some())
        + usize::from(f.destination_mac.is_some())
        + usize::from(f.source_mac.is_some())
        + usize::from(f.vlan_priority.is_some())
        + usize::from(f.vlan_etype.is_some())
        + usize::from(f.vlan_tci.is_some())
        + usize::from(f.user_data.is_some())
}

/// Linux `igc_ethtool_init_nfc_rule` flex condition
/// (igc_ethtool.c:1278-1289): user data, VLAN EtherType, a full-TCI
/// match, or more than one match criterion. Everything else is a
/// single-criterion rule for the ETQF / RAL / VLANPQF tables.
pub(crate) fn is_flex(f: &FlowRule) -> bool {
    f.user_data.is_some() || f.vlan_etype.is_some() || f.vlan_tci.is_some() || criteria(f) > 1
}

/// Two rules program the same hardware filter when every match field
/// agrees (location and queue are the rule's identity/action, not the
/// filter). Linux `igc_ethtool_check_nfc_rule` rejects the second
/// such rule with -EEXIST.
fn same_filter(a: &FlowRule, b: &FlowRule) -> bool {
    a.ethertype == b.ethertype
        && a.destination_mac == b.destination_mac
        && a.source_mac == b.source_mac
        && a.vlan_priority == b.vlan_priority
        && a.vlan_etype == b.vlan_etype
        && a.vlan_tci == b.vlan_tci
        && a.user_data == b.user_data
        && a.user_mask == b.user_mask
}

/// Linux `igc_ethtool_add_nfc_rule` + `igc_ethtool_check_nfc_rule`
/// (igc_ethtool.c:1325-1420) against the hardware tables in
/// `flows()`: locations are the 65-slot `IGC_MAX_RXNFC_RULES` space,
/// but each table behind it is smaller — 8 ETQF, 15 RAL slots after
/// the device address, 8 VLAN priorities, 32 flex filters, 1 default
/// queue (igc.h:670-674). A rule that fits no table is -ENOSPC (28);
/// a duplicate filter is -EEXIST (17); anything else malformed is
/// -EINVAL (22).
pub(crate) fn validate_flows(rules: &[FlowRule], queues: usize, unicast: usize) -> Result<(), i32> {
    let mut locations = alloc::collections::BTreeSet::new();
    let mut etypes = alloc::collections::BTreeSet::new();
    let mut dst_macs = alloc::collections::BTreeSet::new();
    let mut src_macs = alloc::collections::BTreeSet::new();
    let mut prios = 0u8;
    let mut flex_rules: alloc::vec::Vec<&FlowRule> = alloc::vec::Vec::new();
    let mut defaults = 0usize;
    for f in rules {
        if usize::from(f.queue) >= queues || !locations.insert(f.location) || f.location >= 65 {
            return Err(22);
        }
        if f.default_queue {
            if criteria(f) != 0 {
                return Err(22);
            }
            defaults += 1;
            if defaults > 1 {
                return Err(17);
            }
            continue;
        }
        // VLAN priority and a full-TCI match are the same wire field.
        if f.vlan_priority.is_some() && f.vlan_tci.is_some() {
            return Err(22);
        }
        if criteria(f) == 0 {
            return Err(22);
        }
        if let Some(t) = f.ethertype {
            if t < 0x600 {
                return Err(22);
            }
        }
        if let Some(m) = f.destination_mac {
            if !super::hardware::valid_mac(m) {
                return Err(22);
            }
        }
        if let Some(m) = f.source_mac {
            if !super::hardware::valid_mac(m) {
                return Err(22);
            }
        }
        if let Some(p) = f.vlan_priority {
            if p > 7 {
                return Err(22);
            }
        }
        if is_flex(f) {
            if flex_rules.iter().any(|g| same_filter(f, g)) {
                return Err(17);
            }
            flex_rules.push(f);
        } else if let Some(t) = f.ethertype {
            if !etypes.insert(t) {
                return Err(22);
            }
        } else if let Some(m) = f.destination_mac {
            if !dst_macs.insert(m) {
                return Err(22);
            }
        } else if let Some(m) = f.source_mac {
            if !src_macs.insert(m) {
                return Err(22);
            }
        } else if let Some(p) = f.vlan_priority {
            if prios & (1 << p) != 0 {
                return Err(22);
            }
            prios |= 1 << p;
        }
    }
    // The RAL pool check only bites when simple MAC rules exist: a
    // unicast list over 15 is legal on its own (the RCTL overflow bit
    // covers it in `apply_filters`), it just leaves no RAL slot for a
    // MAC filter.
    let mac_rules = dst_macs.len() + src_macs.len();
    if etypes.len() > 8 || (mac_rules > 0 && mac_rules + unicast > 15) || flex_rules.len() > 32 {
        return Err(28);
    }
    Ok(())
}
/// Linux `igc_add_flex_filter` (igc_main.c:3770) +
/// `igc_write_flex_filter_ll` (igc_main.c:3614): one 32-byte flex
/// pattern over the frame head — dst MAC @0, src MAC @6, VLAN EtherType @12, VLAN TCI @14,
/// EtherType @16 (or @12 with no VLAN field), user data @18 (or @14)
/// — written as 16 rows into the FHFT bank selected by
/// `IGC_FHFTSL` (0x5804), with one mask bit per pattern byte, then
/// enabled in WUFC/WUFC_EXT. Queuing is length 32, the rule's queue,
/// priority 0, no immediate interrupt, no drop.
///
/// One deliberate divergence from Linux: `igc_write_flex_filter_ll`
/// enables slot 8 through WUFC bit 24 (`index > 8` instead of
/// `>= 8`), which is not a flex enable at all. NARF enables slot 8
/// through WUFC_EXT bit 8, as `igc_find_avail_flex_filter_slot`
/// expects.
fn write_flex_filter(r: &impl Registers, f: &FlowRule, index: usize) {
    let mut data = [0u8; 128];
    let mut mask = [0u8; 16];
    // Linux `igc_flex_filter_add_field`: copy the field, then set one
    // mask bit per byte — all bits when no mask is given, only the
    // nonzero mask bytes for user data.
    fn add_field(data: &mut [u8; 128], mask: &mut [u8; 16], src: &[u8], offset: usize) {
        data[offset..offset + src.len()].copy_from_slice(src);
        for i in 0..src.len() {
            let idx = i + offset;
            mask[idx / 8] |= 1 << (idx % 8);
        }
    }
    fn add_masked(data: &mut [u8; 128], mask: &mut [u8; 16], src: &[u8], offset: usize, m: &[u8]) {
        data[offset..offset + src.len()].copy_from_slice(src);
        for i in 0..src.len() {
            let idx = i + offset;
            if m[i] != 0 {
                mask[idx / 8] |= 1 << (idx % 8);
            }
        }
    }
    if let Some(m) = f.destination_mac {
        add_field(&mut data, &mut mask, &m, 0);
    }
    if let Some(m) = f.source_mac {
        add_field(&mut data, &mut mask, &m, 6);
    }
    // Linux keys the VLAN offsets on the stored values, not the flags.
    let vlan = f.vlan_tci.is_some_and(|v| v != 0) || f.vlan_etype.is_some_and(|v| v != 0);
    if let Some(t) = f.vlan_etype {
        add_field(&mut data, &mut mask, &t.to_be_bytes(), 12);
    }
    if let Some(t) = f.vlan_tci {
        // Linux copies the stored host-order TCI verbatim.
        add_field(&mut data, &mut mask, &t.to_ne_bytes(), 14);
    } else if let Some(p) = f.vlan_priority {
        // A priority-only rule in a flex filter matches the TCI bytes
        // as Linux stored them: the priority in the PCP field.
        add_field(
            &mut data,
            &mut mask,
            &(u16::from(p) << 13).to_ne_bytes(),
            14,
        );
    }
    if let Some(t) = f.ethertype {
        add_field(
            &mut data,
            &mut mask,
            &t.to_be_bytes(),
            if vlan { 16 } else { 12 },
        );
    }
    if let Some(d) = f.user_data {
        match f.user_mask {
            Some(m) => add_masked(&mut data, &mut mask, &d, if vlan { 18 } else { 14 }, &m),
            None => add_field(&mut data, &mut mask, &d, if vlan { 18 } else { 14 }),
        }
    }
    // Linux `igc_flex_filter_select`: the bank in FHFTSL, then the
    // host-table register for this slot within the bank.
    let bank = (index / 8) as u32;
    r.write(0x5804, (r.read(0x5804) & !0x3) | bank);
    let slot = index % 8;
    let fhft = if slot < 4 {
        0x9000 + slot as u64 * 256
    } else {
        0x9a00 + (slot - 4) as u64 * 256
    };
    // Disable flex queuing while the table is written, as Linux does.
    let wufc = r.read(0x5808) & !(1 << 14);
    r.write(0x5808, wufc);
    let queuing = 32u32 | ((u32::from(f.queue) & 7) << 8);
    r.write(fhft + 0xfc, queuing);
    for i in 0..16 {
        let off = i * 8;
        let dw0 = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        let dw1 = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap());
        let row = fhft + i as u64 * 16;
        r.write(row, dw0);
        r.write(row + 4, dw1);
        let m = r.read(row + 8) & !0xff | u32::from(mask[i]);
        r.write(row + 8, m);
    }
    if index >= 8 {
        r.write(0x580c, r.read(0x580c) | (1 << index));
        r.write(0x5808, wufc | (1 << 14));
    } else {
        r.write(0x5808, wufc | (1 << 14) | (1 << (16 + index)));
    }
}

pub(crate) fn flows(r: &impl Registers, rules: &[FlowRule], first_mac: usize) {
    for n in 0..8 {
        r.write(0x5cb0 + n * 4, 0);
    }
    r.write(0x55b0, 0);
    // Rebuild-from-scratch: drop every flex enable (preserving the
    // WoL wake bits in WUFC/WUFC_EXT) and the MRQC default queue, so
    // a removed rule leaves nothing behind.
    r.write(0x5808, r.read(0x5808) & !(0x4000 | 0xff0000));
    r.write(0x580c, r.read(0x580c) & !0xffffff00);
    r.write(0x5818, r.read(0x5818) & !0x38);
    let mut et = 0;
    let mut mac = first_mac;
    let mut pq = 0;
    let mut flex = 0usize;
    for f in rules {
        if f.default_queue {
            // Linux `igc_set_default_queue_filter`: MRQC bits 5:3.
            r.write(
                0x5818,
                (r.read(0x5818) & !0x38) | ((u32::from(f.queue) & 7) << 3),
            );
            continue;
        }
        if is_flex(f) {
            write_flex_filter(r, f, flex);
            flex += 1;
            continue;
        }
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
        if let Some(m) = f.source_mac {
            // Linux `igc_set_mac_filter_hw`, SRC type: RAH ASEL bit 16.
            r.write(
                0x5400 + mac as u64 * 8,
                u32::from_le_bytes(m[..4].try_into().unwrap()),
            );
            r.write(
                0x5404 + mac as u64 * 8,
                0x90010000
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
