//! Per-context fence references survive replacement of a native submitter.
//! Linux keeps scheduler fences in each context entity; a new GPU owner must
//! not reinterpret an old ticket using its new ring sequences.
use super::JobFence;
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

type Ip = (u32, u32, u32);
/// Completed history retained per logical entity; pending fences are never
/// discarded to meet this cache target. This is a NARF bookkeeping policy.
const KEEP: usize = 64;

#[derive(Debug)]
struct Entity {
    card: u32,
    context: u32,
    ip: Ip,
    jobs: Vec<Arc<JobFence>>,
    recycled: Vec<(u64, u64)>,
}
#[derive(Debug)]
pub(crate) struct History(IrqSafeSpinLock<Vec<Entity>>);
impl History {
    pub const fn new() -> Self {
        Self(IrqSafeSpinLock::new(Vec::new()))
    }
    pub fn forget(&self, context: u32) {
        let mut removed = Vec::new();
        let mut all = self.0.lock();
        let mut i = 0;
        while i < all.len() {
            if all[i].context == context {
                removed.push(all.swap_remove(i));
            } else {
                i += 1;
            }
        }
        drop(all);
        // Dropping the final reference may destroy an old backend owner.
        drop(removed);
    }
    pub fn record(&self, context: u32, ip: Ip, job: Arc<JobFence>) {
        let old = self
            .0
            .lock()
            .iter()
            .find(|e| e.card == job.card && e.context == context && e.ip == ip)
            .filter(|e| e.jobs.len() >= KEEP)
            .and_then(|e| e.jobs.first().cloned());
        // Backend callbacks can retire buffers. Never invoke them with the
        // history lock held. Error signalling alone permits dropping this
        // API reference, not retiring a BO, VMID or page table.
        let prune = old.filter(|f| f.engine.signalled(f.seq));
        let mut all = self.0.lock();
        let index = match all
            .iter()
            .position(|e| e.card == job.card && e.context == context && e.ip == ip)
        {
            Some(i) => i,
            None => {
                all.push(Entity {
                    card: job.card,
                    context,
                    ip,
                    jobs: Vec::new(),
                    recycled: Vec::new(),
                });
                all.len() - 1
            }
        };
        let e = &mut all[index];
        if let Some(prune) = &prune {
            match e
                .recycled
                .iter_mut()
                .find(|(first, _)| *first >> 32 == prune.seq >> 32)
            {
                Some((_, last)) => *last = prune.seq,
                None => e.recycled.push((prune.seq, prune.seq)),
            }
            e.jobs.retain(|f| !Arc::ptr_eq(f, prune));
        }
        let position = e
            .jobs
            .iter()
            .position(|f| {
                Arc::ptr_eq(&f.engine, &job.engine)
                    && (f.seq as u32).wrapping_sub(job.seq as u32) as i32 > 0
            })
            .or_else(|| {
                e.jobs
                    .iter()
                    .rposition(|f| Arc::ptr_eq(&f.engine, &job.engine))
                    .map(|i| i + 1)
            });
        e.jobs.insert(position.unwrap_or(e.jobs.len()), job);
    }
    /// None outside a recorded entity: the legacy ticket resolver remains
    /// available for cards which only provide an issued-ring watermark.
    pub fn resolve(
        &self,
        card: u32,
        context: u32,
        ip: Ip,
        ticket: u64,
    ) -> Option<Result<Option<Arc<JobFence>>, FsError>> {
        let all = self.0.lock();
        let e = all
            .iter()
            .find(|e| e.card == card && e.context == context && e.ip == ip)?;
        if ticket == 0 {
            return Some(Ok(None));
        }
        if ticket == u64::MAX {
            return Some(Ok(e.jobs.last().cloned()));
        }
        if let Some(job) = e.jobs.iter().find(|f| f.seq == ticket) {
            return Some(Ok(Some(job.clone())));
        }
        // Recycled handle windows are already signalled, like
        // amdgpu_ctx_get_fence. Future/cross-ring handles are refused.
        let recycled = e.recycled.iter().any(|&(first, last)| {
            ticket >> 32 == first >> 32
                && (ticket as u32).wrapping_sub(first as u32) as i32 >= 0
                && (last as u32).wrapping_sub(ticket as u32) as i32 >= 0
        });
        Some(if recycled {
            Ok(None)
        } else {
            Err(FsError::InvalidData)
        })
    }
}
