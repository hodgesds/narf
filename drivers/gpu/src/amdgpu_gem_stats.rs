//! Per-card TTM-style counters. Register before client allocation so a frozen
//! relocation commit only updates existing storage: no allocation or callbacks.
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counters {
    pub bytes_moved: u64,
    pub evictions: u64,
}
#[derive(Debug, Default)]
pub(crate) struct CardStats {
    bytes_moved: AtomicU64,
    evictions: AtomicU64,
}
impl CardStats {
    pub(super) fn moved(&self, bytes: u64) {
        self.bytes_moved.fetch_add(bytes, Ordering::Relaxed);
    }
    pub(super) fn evicted(&self) {
        self.evictions.fetch_add(1, Ordering::Relaxed);
    }
}
static CARDS: IrqSafeSpinLock<Vec<(u32, Arc<CardStats>)>> = IrqSafeSpinLock::new(Vec::new());

pub(super) fn register(card: u32) -> Arc<CardStats> {
    let mut cards = CARDS.lock();
    if let Some((_, stats)) = cards.iter().find(|(c, _)| *c == card) {
        return stats.clone();
    }
    let stats = Arc::new(CardStats::default());
    cards.push((card, stats.clone()));
    stats
}
pub(super) fn for_card(card: Option<u32>) -> Option<Arc<CardStats>> {
    card.map(register)
}
/// Card indices are never reused. Keep cumulative counts across heap recovery.
pub(crate) fn counters(card: u32) -> Counters {
    let stats = CARDS
        .lock()
        .iter()
        .find(|(c, _)| *c == card)
        .map(|(_, stats)| stats.clone());
    stats.map_or(Counters::default(), |s| Counters {
        bytes_moved: s.bytes_moved.load(Ordering::Relaxed),
        evictions: s.evictions.load(Ordering::Relaxed),
    })
}
