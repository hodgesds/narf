//! Per-object i915 implicit dependency admission. Linux b90c984d
//! i915_gem_execbuffer.c::eb_move_to_gpu and i915_vma.c::_i915_vma_move_to_active:
//! ASYNC skips the earlier await, never active ownership or READ/WRITE fences.
use super::{GemObject, RESERVATIONS};
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::{
    dma_buf::{dma_resv_usage_rw, DmaResvFence, DmaResvUsage},
    FsError,
};

/// One atomic mixed transaction. All foreign fence callbacks and retired
/// references stay outside RESERVATIONS. Aliases fold to the strongest access
/// and any synchronous use of their one underlying reservation identity.
pub(crate) fn reserve_gpu_mixed(
    objects: &[(Arc<GemObject>, bool)],
    asynchronous: &[bool],
    completion: &Arc<crate::intel_gpu_fence::CompletionFence>,
) -> Result<(), FsError> {
    if objects.len() != asynchronous.len() || objects.len() > 4096 {
        return Err(FsError::InvalidData);
    }
    let mut unique: Vec<(Arc<GemObject>, bool, bool)> = Vec::new();
    unique
        .try_reserve_exact(objects.len())
        .map_err(|_| FsError::OutOfMemory)?;
    for ((object, writable), asynchronous) in objects.iter().zip(asynchronous) {
        if let Some((_, write, implicit)) = unique
            .iter_mut()
            .find(|(old, _, _)| Arc::ptr_eq(old, object))
        {
            *write |= *writable;
            *implicit |= !*asynchronous;
        } else {
            unique.push((object.clone(), *writable, !*asynchronous));
        }
    }
    let prepared = DmaResvFence::new(completion.clone());
    let snapshots: Vec<_> = unique
        .iter()
        .map(|(object, _, _)| object.dma_buf.resv.snapshot())
        .collect();
    if snapshots
        .iter()
        .zip(&unique)
        .any(|(snapshot, (_, write, implicit))| {
            *implicit && snapshot.has_fences(dma_resv_usage_rw(*write))
        })
    {
        return Err(FsError::WouldBlock);
    }
    let mut retired = Vec::new();
    retired
        .try_reserve_exact(unique.len())
        .map_err(|_| FsError::OutOfMemory)?;
    {
        let _gate = RESERVATIONS.lock();
        // Only synchronous uses made a prior-conflict decision. An ASYNC
        // snapshot may be stale: add_prepared can prune only its proven-dead
        // entries and always preserves a later live fence.
        if snapshots
            .iter()
            .zip(&unique)
            .any(|(snapshot, (_, _, implicit))| *implicit && !snapshot.is_current())
        {
            return Err(FsError::WouldBlock);
        }
        for ((object, write, _), snapshot) in unique.iter().zip(&snapshots) {
            retired.push(object.dma_buf.resv.add_prepared(
                snapshot,
                &[(
                    prepared.clone(),
                    if *write {
                        DmaResvUsage::Write
                    } else {
                        DmaResvUsage::Read
                    },
                )],
            ));
        }
    }
    drop(retired);
    Ok(())
}
