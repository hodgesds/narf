//! Xe sync arrays retain exact payloads and signal cores before any await.
use crate::{
    drm::syncobj::{self as so, DmaFence, SyncObjCore, SyncObjTable},
    intel_gpu_uapi::{u32_at, u64_at},
    intel_gpu_xe_vm::{read, zero},
};
use alloc::{sync::Arc, vec::Vec};
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

pub(crate) struct Sync {
    waits: Vec<Arc<dyn DmaFence>>,
    outputs: Vec<(Arc<SyncObjCore>, u64)>,
    pub user_fence: Option<(u64, u64)>,
}
impl Sync {
    pub fn read(
        user: &dyn IoctlContext,
        address: u64,
        count: u32,
        table: &IrqSafeSpinLock<SyncObjTable>,
    ) -> Result<Self, FsError> {
        if count > 1024 {
            return Err(FsError::InvalidData);
        }
        let wire = read(user, address, count as usize * 48)?;
        let mut result = Self {
            waits: Vec::new(),
            outputs: Vec::new(),
            user_fence: None,
        };
        for entry in wire.chunks_exact(48) {
            zero(&entry[0..8])?;
            zero(&entry[32..48])?;
            let kind = u32_at(entry, 8);
            let flags = u32_at(entry, 12);
            let handle = u64_at(entry, 16);
            let point = u64_at(entry, 24);
            if flags > 1 {
                return Err(FsError::InvalidData);
            }
            if kind == 2 {
                if flags != 1 {
                    return Err(FsError::NotImplemented);
                }
                if handle & 7 != 0 || result.user_fence.replace((handle, point)).is_some() {
                    return Err(FsError::InvalidData);
                }
                continue;
            }
            if kind > 1 || handle > u32::MAX as u64 || (kind == 1 && point == 0) {
                return Err(FsError::InvalidData);
            }
            let core = table
                .lock()
                .get(handle as u32)
                .map_err(|_| FsError::NotFound)?
                .core()
                .clone();
            if flags == 1 {
                result
                    .outputs
                    .push((core, if kind == 0 { 0 } else { point }));
            } else {
                let payload = core.fence().ok_or(FsError::InvalidData)?;
                let fence = if kind == 0 {
                    payload
                } else {
                    so::find_seqno(Some(payload), point)
                        .map_err(|_| FsError::InvalidData)?
                        .unwrap_or_else(so::stub)
                };
                result.waits.push(fence);
            }
        }
        Ok(result)
    }
    pub async fn wait(&self) {
        while self.waits.iter().any(|fence| !fence.is_signalled()) {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
    pub fn publish(&self, fence: Arc<dyn DmaFence>) {
        for (core, point) in &self.outputs {
            if *point == 0 {
                core.replace_fence(Some(fence.clone()));
            } else {
                core.add_point(fence.clone(), *point);
            }
        }
    }
}
