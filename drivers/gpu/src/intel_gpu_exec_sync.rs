//! i915 explicit submission synchronization, Linux MIT b90c984d615e8ce2af96f5b1411a962d83fed2ad:
//! i915_gem_execbuffer.c (fence arrays and timeline extensions), drm_syncobj.c.
use crate::{
    drm::syncobj::{self as so, SyncObjCore, SyncObjTable},
    intel_gpu_fence::CompletionFence,
    intel_gpu_uapi::{self as abi, u32_at, u64_at},
};
use alloc::{collections::BTreeSet, sync::Arc, vec, vec::Vec};
use narf_filesystem::{DrmFence, FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

const MAX_FENCES: usize = 4096;
#[derive(Debug)]
struct Entry {
    handle: u32,
    flags: u32,
    point: u64,
    timeline: bool,
}
struct Dependency {
    fence: Arc<dyn DrmFence>,
    submit: bool,
}
pub(crate) struct SyncRequest {
    pub output: bool,
    pub input_word: u32,
    entries: Vec<Entry>,
    dependencies: Vec<Dependency>,
}
pub(crate) struct Resolved {
    dependencies: Vec<Dependency>,
    signals: Vec<(Arc<SyncObjCore>, u64)>,
}

fn read(user: &dyn IoctlContext, address: u64, bytes: usize) -> Result<Vec<u8>, FsError> {
    if bytes == 0 {
        return Ok(Vec::new());
    }
    address
        .checked_add(bytes as u64)
        .ok_or(FsError::BadAddress)?;
    let mut data = vec![0; bytes];
    user.read(address, &mut data)?;
    Ok(data)
}
impl SyncRequest {
    pub fn read(user: &dyn IoctlContext, wire: &[u8; 64]) -> Result<Self, FsError> {
        let flags = u64_at(wire, 40);
        let array = flags & abi::EXEC_FENCE_ARRAY != 0;
        let extensions = flags & abi::EXEC_USE_EXTENSIONS != 0;
        let count = u32_at(wire, 28) as usize;
        let pointer = u64_at(wire, 32);
        if (array && extensions)
            || (!array && count != 0)
            || (!array && !extensions && pointer != 0)
        {
            return Err(FsError::InvalidData);
        }
        let input_word = u64_at(wire, 56) as u32;
        let inputs = flags & (abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT);
        if inputs == abi::EXEC_FENCE_IN | abi::EXEC_FENCE_SUBMIT {
            return Err(FsError::InvalidData);
        }
        let mut result = Self {
            output: flags & abi::EXEC_FENCE_OUT != 0,
            input_word,
            entries: Vec::new(),
            dependencies: Vec::new(),
        };
        if inputs != 0 {
            let fences = user
                .sync_file_fences(input_word as i32)
                .ok_or(FsError::InvalidData)?;
            if fences.len() > MAX_FENCES {
                return Err(FsError::OutOfMemory);
            }
            result.dependencies = fences
                .into_iter()
                .map(|fence| Dependency {
                    fence,
                    submit: inputs == abi::EXEC_FENCE_SUBMIT,
                })
                .collect();
        } else if !result.output && u64_at(wire, 56) != 0 {
            return Err(FsError::InvalidData);
        }
        if array {
            result.array(user, pointer, count, None)?;
        }
        if extensions {
            let mut address = pointer;
            let mut seen = BTreeSet::new();
            while address != 0 {
                if seen.len() == 16 || !seen.insert(address) {
                    return Err(FsError::InvalidData);
                }
                let ext = read(user, address, 56)?;
                if u32_at(&ext, 8) != 0 || ext[12..32].iter().any(|b| *b != 0) {
                    return Err(FsError::InvalidData);
                }
                let count = usize::try_from(u64_at(&ext, 32)).map_err(|_| FsError::InvalidData)?;
                result.array(user, u64_at(&ext, 40), count, Some(u64_at(&ext, 48)))?;
                address = u64_at(&ext, 0);
            }
        }
        Ok(result)
    }
    fn array(
        &mut self,
        user: &dyn IoctlContext,
        address: u64,
        count: usize,
        values: Option<u64>,
    ) -> Result<(), FsError> {
        if count > MAX_FENCES - self.entries.len() {
            return Err(FsError::InvalidData);
        }
        let entries = read(user, address, count * 8)?;
        let points = match values {
            Some(address) => read(user, address, count * 8)?,
            None => Vec::new(),
        };
        for (i, entry) in entries.chunks_exact(8).enumerate() {
            let flags = u32_at(entry, 4);
            let point = if values.is_some() {
                u64_at(&points, i * 8)
            } else {
                0
            };
            if flags & !3 != 0 || (point != 0 && flags == 3) {
                return Err(FsError::InvalidData);
            }
            self.entries.push(Entry {
                handle: u32_at(entry, 0),
                flags,
                point,
                timeline: values.is_some(),
            });
        }
        Ok(())
    }
    pub fn resolve(self, table: &IrqSafeSpinLock<SyncObjTable>) -> Result<Resolved, FsError> {
        let mut result = Resolved {
            dependencies: self.dependencies,
            signals: Vec::new(),
        };
        // Retain objects and exact input payloads before any wait or publication;
        // handle destruction/replacement in another thread cannot retarget them.
        for entry in self.entries {
            let core = table
                .lock()
                .get(entry.handle)
                .map_err(|_| FsError::NotFound)?
                .core()
                .clone();
            let payload = core.fence();
            let dependency = if entry.timeline {
                if payload.is_none() && entry.flags != 0 && entry.flags & 2 == 0 {
                    return Err(FsError::InvalidData);
                }
                match so::find_seqno(payload.clone(), entry.point) {
                    Ok(fence) => fence,
                    Err(()) if payload.is_none() && entry.flags == 0 => None,
                    Err(()) if entry.flags & 2 != 0 => payload,
                    Err(()) => return Err(FsError::InvalidData),
                }
            } else if entry.flags & 1 != 0 {
                Some(payload.ok_or(FsError::InvalidData)?)
            } else {
                None
            };
            if let Some(fence) = dependency {
                result
                    .dependencies
                    .extend(
                        so::to_drm_leaves(&fence)
                            .into_iter()
                            .map(|fence| Dependency {
                                fence,
                                submit: false,
                            }),
                    );
                if result.dependencies.len() > MAX_FENCES {
                    return Err(FsError::OutOfMemory);
                }
            }
            if entry.flags & 2 != 0 {
                result.signals.push((core, entry.point));
            }
        }
        Ok(result)
    }
}
impl Resolved {
    pub async fn wait(&self) {
        while self.dependencies.iter().any(|dependency| {
            if dependency.submit {
                !dependency.fence.is_submit_ready()
            } else {
                !dependency.fence.is_signalled()
            }
        }) {
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
    pub fn publish(self, fence: Arc<CompletionFence>) {
        if self.signals.is_empty() {
            return;
        }
        let fence = so::from_drm_leaves(vec![fence]);
        for (core, point) in self.signals {
            if point == 0 {
                core.replace_fence(Some(fence.clone()));
            } else {
                core.add_point(fence.clone(), point);
            }
        }
    }
}
