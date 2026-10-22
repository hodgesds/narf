//! Typed physical claims shared by both kernel ioremap implementations.
//! Pending installation and teardown keep their claims while the cache lock
//! is released for page-table allocation and TLB shootdowns.
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    BadRange,
    Conflict,
    Busy,
    Exhausted,
}
struct Entry<A, M> {
    id: u64,
    phys: u64,
    end: u64,
    attrs: A,
    ready: Option<M>,
}
pub(crate) struct Cache<A: Copy + Eq, M: Copy> {
    entries: Vec<Entry<A, M>>,
    next: u64,
}
impl<A: Copy + Eq, M: Copy> Cache<A, M> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next: 0,
        }
    }
}
pub(crate) enum Claim<'a, A: Copy + Eq, M: Copy> {
    Ready(M),
    Pending(Reservation<'a, A, M>),
}
/// Dropping an unpublished claim releases it, after the caller has removed
/// any partial leaves. Publishing converts it to a reusable ready entry.
pub(crate) struct Reservation<'a, A: Copy + Eq, M: Copy> {
    cache: &'a IrqSafeSpinLock<Cache<A, M>>,
    id: u64,
    pending: bool,
}
impl<A: Copy + Eq, M: Copy> Reservation<'_, A, M> {
    pub(crate) fn publish(mut self, mapping: M) {
        let mut cache = self.cache.lock();
        let entry = cache
            .entries
            .iter_mut()
            .find(|e| e.id == self.id)
            .expect("ioremap claim");
        assert!(entry.ready.is_none());
        entry.ready = Some(mapping);
        self.pending = false;
    }
}
impl<A: Copy + Eq, M: Copy> Drop for Reservation<'_, A, M> {
    fn drop(&mut self) {
        if self.pending {
            self.cache.lock().entries.retain(|e| e.id != self.id);
        }
    }
}
/// Check every overlapping pending/ready claim before allowing a compatible
/// new interval. Identical ready ranges reuse the VA; an identical pending
/// claim is busy, so a racing caller cannot allocate a second copy.
pub(crate) fn claim<A: Copy + Eq, M: Copy>(
    cache: &IrqSafeSpinLock<Cache<A, M>>,
    phys: u64,
    len: u64,
    attrs: A,
) -> Result<Claim<'_, A, M>, Error> {
    let end = phys
        .checked_add(len)
        .filter(|_| len != 0)
        .ok_or(Error::BadRange)?;
    let mut guard = cache.lock();
    for entry in &guard.entries {
        if phys < entry.end && entry.phys < end && entry.attrs != attrs {
            return Err(Error::Conflict);
        }
    }
    if let Some(entry) = guard
        .entries
        .iter()
        .find(|e| e.phys == phys && e.end == end)
    {
        return match entry.ready {
            Some(mapping) => Ok(Claim::Ready(mapping)),
            None => Err(Error::Busy),
        };
    }
    let id = guard.next.checked_add(1).ok_or(Error::Exhausted)?;
    guard.entries.try_reserve(1).map_err(|_| Error::Exhausted)?;
    guard.next = id;
    guard.entries.push(Entry {
        id,
        phys,
        end,
        attrs,
        ready: None,
    });
    drop(guard);
    Ok(Claim::Pending(Reservation {
        cache,
        id,
        pending: true,
    }))
}
/// Keep the typed interval reserved until unmapping and all shootdowns have
/// completed. It becomes busy instead of reusable during teardown.
pub(crate) fn retire<A: Copy + Eq, M: Copy>(
    cache: &IrqSafeSpinLock<Cache<A, M>>,
    matches: impl Fn(M) -> bool,
) -> Option<Reservation<'_, A, M>> {
    let mut guard = cache.lock();
    let entry = guard
        .entries
        .iter_mut()
        .find(|e| e.ready.is_some_and(&matches))?;
    entry.ready = None;
    let id = entry.id;
    drop(guard);
    Some(Reservation {
        cache,
        id,
        pending: true,
    })
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn pending<A: Copy + Eq, M: Copy>(claim: Claim<'_, A, M>) -> Reservation<'_, A, M> {
        match claim {
            Claim::Pending(r) => r,
            Claim::Ready(_) => panic!("new ioremap claim reused"),
        }
    }
    fn typed_ioremap_claims_exclude_conflicting_aliases_and_races() -> TestResult {
        let cache = IrqSafeSpinLock::new(Cache::<u8, u64>::new());
        let a = pending(claim(&cache, 0x2000, 0x2000, 1).unwrap());
        assert!(matches!(claim(&cache, 0x2000, 0x2000, 1), Err(Error::Busy)));
        for (base, len) in [(0x2000, 0x2000), (0x1000, 0x2000), (0x3000, 0x2000)] {
            assert!(matches!(claim(&cache, base, len, 2), Err(Error::Conflict)));
        }
        // No lock escapes claim: a caller can acquire it while allocating
        // page tables, and independent nonoverlapping mappings can proceed.
        assert!(cache.try_lock().is_some());
        drop(pending(claim(&cache, 0x4000, 0x1000, 2).unwrap()));
        a.publish(0xdead_0000);
        assert!(matches!(
            claim(&cache, 0x2000, 0x2000, 1),
            Ok(Claim::Ready(0xdead_0000))
        ));
        let old = retire(&cache, |m| m == 0xdead_0000).unwrap();
        assert!(matches!(claim(&cache, 0x2000, 0x2000, 1), Err(Error::Busy)));
        assert!(matches!(
            claim(&cache, 0x2000, 0x1000, 2),
            Err(Error::Conflict)
        ));
        drop(old); // Old leaves and TLB entries have now been removed.
        drop(pending(claim(&cache, 0x2000, 0x2000, 2).unwrap()));
        assert!(cache.lock().entries.is_empty());
        assert!(matches!(
            claim(&cache, u64::MAX - 1, 4, 1),
            Err(Error::BadRange)
        ));
        TestResult::Pass
    }
    fn failed_ioremap_install_releases_only_its_pending_claim() -> TestResult {
        let cache = IrqSafeSpinLock::new(Cache::<u8, u64>::new());
        pending(claim(&cache, 0x1000, 0x1000, 1).unwrap()).publish(0xaaaa);
        {
            let _failed = pending(claim(&cache, 0x3000, 0x1000, 1).unwrap());
            assert!(matches!(
                claim(&cache, 0x3000, 0x1000, 2),
                Err(Error::Conflict)
            ));
        }
        // Simulates vmalloc or page-table failure after partial leaves were
        // rolled back; unrelated ready mappings remain published.
        drop(pending(claim(&cache, 0x3000, 0x1000, 2).unwrap()));
        assert!(matches!(
            claim(&cache, 0x1000, 0x1000, 1),
            Ok(Claim::Ready(0xaaaa))
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/ioremap",
        typed_ioremap_claims_exclude_conflicting_aliases_and_races
    );
    kernel_test_in!(
        "memory/ioremap",
        failed_ioremap_install_releases_only_its_pending_claim
    );
}
