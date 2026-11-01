//! Per-function GGTT reservation ledger. Fixed console/primary/GT ranges are
//! idempotent policy reservations; DMA command allocations hold exclusive
//! leases. Installed DSB mappings stay on the same BO/VA for the whole display
//! owner's lifetime; this module does not claim a display TLB invalidation.
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

const MIB: u64 = 1024 * 1024;
const DSB_START: u64 = 144 * MIB;
const DSB_END: u64 = 160 * MIB;
static CARDS: IrqSafeSpinLock<Vec<(u64, Arc<Ledger>)>> = IrqSafeSpinLock::new(Vec::new());
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Console(u8),
    Primary,
    Gt,
}
#[derive(Debug)]
pub(crate) struct Ledger {
    capacity: u64,
    live: IrqSafeSpinLock<Vec<(u64, u64)>>,
}
impl Ledger {
    pub(crate) fn for_bar(key: u64, bar_len: u64) -> Result<Arc<Self>, FsError> {
        let capacity = crate::intel_gpu_gtt::ggtt_va_size(bar_len);
        if capacity == 0 {
            return Err(FsError::NoDevice);
        }
        let mut cards = CARDS.lock();
        if let Some((_, old)) = cards.iter().find(|(id, _)| *id == key) {
            return if old.capacity == capacity {
                Ok(old.clone())
            } else {
                Err(FsError::Busy)
            };
        }
        let ledger = Arc::new(Self {
            capacity,
            live: IrqSafeSpinLock::new(Vec::new()),
        });
        cards.push((key, ledger.clone()));
        Ok(ledger)
    }
    pub(crate) fn allows(&self, kind: Kind, start: u64, bytes: u64) -> bool {
        let (low, high) = match kind {
            Kind::Console(pipe) if pipe < 4 => (
                (16 + u64::from(pipe) * 32) * MIB,
                (48 + u64::from(pipe) * 32) * MIB,
            ),
            Kind::Console(_) => return false,
            Kind::Primary => (160 * MIB, 256 * MIB),
            Kind::Gt => (
                u64::from(crate::intel_gpu_rcs::GGTT_ARENA_BASE),
                u64::from(crate::intel_gpu_rcs::GGTT_ARENA_BASE)
                    + u64::from(crate::intel_gpu_rcs::GGTT_ARENA_PAGES) * 4096,
            ),
        };
        bytes != 0
            && start >= low
            && start % 4096 == 0
            && start
                .checked_add(bytes)
                .is_some_and(|end| end <= high && end <= self.capacity)
    }
    pub(crate) fn reserve_dsb(self: &Arc<Self>, bytes: u64) -> Result<Lease, FsError> {
        if bytes == 0 || bytes % 4096 != 0 || bytes > DSB_END - DSB_START || DSB_END > self.capacity
        {
            return Err(FsError::Unsupported);
        }
        let mut live = self.live.lock();
        let mut start = DSB_START;
        loop {
            let end = start + bytes;
            if end > DSB_END {
                return Err(FsError::OutOfMemory);
            }
            if let Some(&(_, other_end)) = live.iter().find(|&&(a, b)| start < b && a < end) {
                start = other_end;
                continue;
            }
            live.push((start, end));
            return Ok(Lease {
                ledger: self.clone(),
                start,
                bytes,
            });
        }
    }
}
/// An uninstalled reservation may be dropped. Once command PTEs are exposed,
/// the production DMA owner retains/forgets this lease with its unchanged BO
/// and IO owner, including after natural command completion.
#[derive(Debug)]
pub(crate) struct Lease {
    ledger: Arc<Ledger>,
    pub(crate) start: u64,
    pub(crate) bytes: u64,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.ledger
            .live
            .lock()
            .retain(|&(a, b)| (a, b) != (self.start, self.start + self.bytes));
    }
}
