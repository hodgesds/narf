//! Dynamic interrupt moderation: Linux `igc_update_ring_itr`, the policy igc
//! applies to every queue vector when the adapter has more than one
//! (`igc_ring_irq_enable`), under the default `rx_itr_setting` of 3.
//!
//! EITR values are in the device's 0.25 us interval units, as Linux's.

/// `IGC_START_ITR`: ~6000 interrupts/s, the value a vector starts with.
pub(crate) const START_ITR: u32 = 648;
/// `IGC_4K_ITR`: the fixed rate below gigabit.
pub(crate) const ITR_4K: u32 = 980;
/// `IGC_20K_ITR`: conservative mode's floor.
pub(crate) const ITR_20K: u32 = 196;
/// `IGC_QVECTOR_MASK`: the EITR interval field.
const INTERVAL_MASK: u32 = 0x7ffc;
/// `IGC_EITR_CNT_IGNR`: write the interval without the counter.
const CNT_IGNR: u32 = 1 << 31;

/// Linux `rx_itr_setting` semantics of an `ethtool -C rx-usecs` value:
/// 1 is dynamic, 3 dynamic-conservative (the default), anything else a
/// fixed interval (0 being none). `Some(conservative)` for the dynamic modes.
pub(crate) const fn dynamic_mode(coalesce_us: u32) -> Option<bool> {
    match coalesce_us {
        1 => Some(false),
        3 => Some(true),
        _ => None,
    }
}

/// The EITR word for an interval (`igc_write_itr`).
pub(crate) const fn eitr(itr: u32) -> u32 {
    let interval = itr & INTERVAL_MASK;
    (if interval == 0 {
        INTERVAL_MASK
    } else {
        interval
    }) | CNT_IGNR
}

/// Work one vector completed since its last re-arm.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Work {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

/// `igc_update_ring_itr`: the next interval for a vector now at `current`.
/// It follows the larger mean frame of either direction (plus 24 bytes of
/// CRC, preamble and gap, capped at 3000 so jumbo frames are not starved):
/// half of it, a third for mid-size frames; conservative mode never goes
/// below 20K interrupts/s. 10/100 Mb/s links stay at 4K interrupts/s. No
/// work leaves the interval alone.
pub(crate) fn ring_itr(
    current: u32,
    speed_mbps: Option<u32>,
    conservative: bool,
    work: Work,
) -> u32 {
    if matches!(speed_mbps, Some(10 | 100)) {
        return ITR_4K;
    }
    let mean = |bytes: u64, packets: u64| if packets == 0 { 0 } else { bytes / packets };
    let wire = mean(work.rx_bytes, work.rx_packets).max(mean(work.tx_bytes, work.tx_packets));
    if wire == 0 {
        return current;
    }
    let wire = (wire + 24).min(3000) as u32;
    let next = if wire > 300 && wire < 1200 {
        wire / 3
    } else {
        wire / 2
    };
    if conservative && next < ITR_20K {
        ITR_20K
    } else {
        next
    }
}
