//! Persistent Xe VM metadata. Each execution receives private immutable tables;
//! binds serialize with prior submissions before publishing a new mapping set.
use crate::{
    intel_gpu_exec::VmMapping,
    intel_gpu_fence::CompletionFence,
    intel_gpu_gem::GemState,
    intel_gpu_gt::GtPlatform,
    intel_gpu_uapi::{u32_at, u64_at},
};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::mutex::Mutex;

static NEXT_VM: AtomicU64 = AtomicU64::new(1);
pub(crate) const MAX_MAPPINGS: usize = 4096;
pub(crate) const MAX_VA: u64 = 1 << 48;

#[derive(Debug)]
pub(crate) struct Vm {
    pub identity: u64,
    pub scratch: bool,
    pub dead: AtomicBool,
    pub state: Mutex<State>,
}
#[derive(Debug)]
pub(crate) struct State {
    pub mappings: Vec<VmMapping>,
    pub active: Vec<Arc<CompletionFence>>,
}
impl Vm {
    pub fn new(scratch: bool) -> Result<Arc<Self>, FsError> {
        let identity = NEXT_VM
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .map_err(|_| FsError::OutOfMemory)?;
        Ok(Arc::new(Self {
            identity,
            scratch,
            dead: AtomicBool::new(false),
            state: Mutex::new(State {
                mappings: Vec::new(),
                active: Vec::new(),
            }),
        }))
    }
    pub fn check(&self) -> Result<(), FsError> {
        if self.dead.load(Ordering::Acquire) {
            Err(FsError::NotFound)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) struct Bind {
    pub object: Option<Arc<crate::intel_gpu_gem::GemObject>>,
    pub address: u64,
    pub length: u64,
    pub op: u32,
    pub mapping: Option<VmMapping>,
    /// MAP_USERPTR source address, pinned only after every op's arguments
    /// validate (Linux checks all ops before faulting any pages).
    pub userptr: Option<u64>,
}

/// PAT indices coherent with CPU caches that this driver programs.
pub(crate) fn pat_allowed(platform: GtPlatform, pat: u16) -> bool {
    match platform {
        GtPlatform::Alchemist => pat == 0,
        GtPlatform::Battlemage => matches!(pat, 1 | 2 | 4 | 5 | 7),
        GtPlatform::Integrated(_) => matches!(pat, 3 | 4),
    }
}

/// Programmed XE_COH_NONE indices: Xe-LPG PAT1 (WT) and PAT2 (UC). Linux
/// also admits PAT0, whose definition this driver leaves to firmware for the
/// inherited display, so it stays refused.
pub(crate) fn pat_noncoherent(platform: GtPlatform, pat: u16) -> bool {
    matches!(platform, GtPlatform::Integrated(_)) && matches!(pat, 1 | 2)
}

impl Bind {
    pub fn read(
        wire: &[u8],
        vm: &Vm,
        gem: &GemState,
        platform: GtPlatform,
    ) -> Result<Self, FsError> {
        if u64_at(wire, 0) != 0 || wire[14..16] != [0; 2] || wire[52..80].iter().any(|b| *b != 0) {
            return Err(FsError::InvalidData);
        }
        let object = u32_at(wire, 8);
        let pat = u16::from_le_bytes(wire[12..14].try_into().unwrap());
        let offset = u64_at(wire, 16);
        let length = u64_at(wire, 24);
        let address = u64_at(wire, 32);
        let op = u32_at(wire, 40);
        let flags = u32_at(wire, 44);
        // op > DRM_XE_VM_BIND_OP_PREFETCH is EINVAL; PREFETCH itself is a
        // valid operation that this VM does not implement.
        if flags & !0x1f != 0 || u32_at(wire, 48) != 0 || op > 4 {
            return Err(FsError::InvalidData);
        }
        if op == 3 {
            if object == 0 || address != 0 || length != 0 || flags & 4 != 0 {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: Some(gem.object(object)?),
                address,
                length,
                op,
                mapping: None,
                userptr: None,
            });
        }
        if address % 4096 != 0
            || length == 0
            || length % 4096 != 0
            || address.checked_add(length).is_none_or(|end| end > MAX_VA)
        {
            return Err(FsError::InvalidData);
        }
        if op == 1 {
            if object != 0 || flags & 4 != 0 {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: None,
                address,
                length,
                op,
                mapping: None,
                userptr: None,
            });
        }
        if op == 2 {
            // DRM_XE_VM_BIND_OP_MAP_USERPTR (vm_bind_ioctl_check_args): no
            // object, not NULL, a coherent uncompressed PAT and an aligned
            // address. Every admitted PAT is coherent and uncompressed.
            if object != 0 || flags & 4 != 0 || !pat_allowed(platform, pat) || offset % 4096 != 0 {
                return Err(FsError::InvalidData);
            }
            return Ok(Self {
                object: None,
                address,
                length,
                op: 0,
                mapping: Some(VmMapping {
                    object: None,
                    va: address,
                    offset: 0,
                    length,
                    writable: flags & 1 == 0,
                    pat: pat as u8,
                }),
                userptr: Some(offset),
            });
        }
        if op != 0 {
            return Err(FsError::NotImplemented);
        }
        let null = flags & 4 != 0;
        let object_arc = if null {
            if object != 0 || offset != 0 || flags & 1 != 0 || pat > 15 {
                return Err(FsError::InvalidData);
            }
            None
        } else {
            let noncoherent = pat_noncoherent(platform, pat);
            if !(pat_allowed(platform, pat) || noncoherent) || offset % 4096 != 0 {
                return Err(FsError::InvalidData);
            }
            let object = gem.object(object)?;
            // xe_vm_bind_ioctl_validate_bo: XE_COH_NONE on a WB object would
            // let the GPU miss dirty CPU lines (or the CPU miss GPU writes).
            if (noncoherent && !object.is_wc())
                || object.vm_owner().is_some_and(|owner| owner != vm.identity)
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > object.size())
            {
                return Err(FsError::InvalidData);
            }
            Some(object)
        };
        Ok(Self {
            object: None,
            address,
            length,
            op,
            mapping: Some(VmMapping {
                object: object_arc,
                va: address,
                offset,
                length,
                writable: flags & 1 == 0,
                pat: pat as u8,
            }),
            userptr: None,
        })
    }

    /// Fault in and pin a MAP_USERPTR range (write-resolving unless READONLY)
    /// as a VM-private object. Pins are snapshot lifetime holds: jobs and
    /// mappings retain them, so the GPU never reaches freed memory.
    pub fn pin(&mut self, vm: &Vm, user: &dyn IoctlContext) -> Result<(), FsError> {
        let Some(address) = self.userptr else {
            return Ok(());
        };
        let mapping = self.mapping.as_mut().expect("userptr mapping");
        let pins = user.pin_user_pages(address, mapping.length / 4096, mapping.writable)?;
        mapping.object = Some(crate::intel_gpu_gem::GemObject::from_user_pins(
            pins,
            vm.identity,
        )?);
        Ok(())
    }
}

/// Remove an interval, preserving left/right slices and their object offsets.
fn remove(mappings: &mut Vec<VmMapping>, start: u64, length: u64) {
    let end = start + length;
    let mut retained = Vec::new();
    for mapping in mappings.drain(..) {
        let limit = mapping.va + mapping.length;
        if limit <= start || mapping.va >= end {
            retained.push(mapping);
            continue;
        }
        if mapping.va < start {
            let mut left = mapping.clone();
            left.length = start - mapping.va;
            retained.push(left);
        }
        if limit > end {
            let mut right = mapping;
            right.offset += end - right.va;
            right.va = end;
            right.length = limit - end;
            retained.push(right);
        }
    }
    *mappings = retained;
}

impl State {
    pub fn prepare(&self, binds: &[Bind], scratch: bool) -> Result<Vec<VmMapping>, FsError> {
        let mut mappings = self.mappings.clone();
        for bind in binds {
            if bind.op == 3 {
                let object = bind.object.as_ref().expect("retained unmap object");
                mappings.retain(|m| {
                    !m.object
                        .as_ref()
                        .is_some_and(|old| Arc::ptr_eq(old, object))
                });
            } else {
                remove(&mut mappings, bind.address, bind.length);
                if let Some(mapping) = &bind.mapping {
                    mappings.push(mapping.clone());
                }
            }
            if mappings.len() > MAX_MAPPINGS {
                return Err(FsError::OutOfMemory);
            }
        }
        mappings.sort_unstable_by_key(|m| m.va);
        let bytes = mappings
            .iter()
            .filter(|m| m.object.is_some() || !scratch)
            .try_fold(0u64, |sum, m| sum.checked_add(m.length))
            .ok_or(FsError::OutOfMemory)?;
        if bytes > 512 * 1024 * 1024 {
            return Err(FsError::OutOfMemory);
        }
        Ok(mappings)
    }

    pub async fn retire(&mut self) -> Result<(), FsError> {
        for fence in &self.active {
            fence
                .wait()
                .await
                .map_err(|_| crate::intel_gpu_user::io_error())?;
        }
        self.active.clear();
        Ok(())
    }
}

pub(crate) fn read(
    user: &dyn IoctlContext,
    address: u64,
    count: usize,
) -> Result<Vec<u8>, FsError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    address
        .checked_add(count as u64)
        .ok_or(FsError::BadAddress)?;
    let mut wire = alloc::vec![0; count];
    user.read(address, &mut wire)?;
    Ok(wire)
}
pub(crate) fn zero(wire: &[u8]) -> Result<(), FsError> {
    if wire.iter().any(|byte| *byte != 0) {
        Err(FsError::InvalidData)
    } else {
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_xe_vm_interval_split_replace_and_atomic_failure() -> TestResult {
        let gem = GemState::new();
        let mut handle = 0;
        gem.create(16384, |h, _| {
            handle = h;
            Ok(())
        })
        .unwrap();
        let state = State {
            mappings: alloc::vec![VmMapping {
                object: Some(gem.object(handle).unwrap()),
                va: 0x10000,
                offset: 0,
                length: 16384,
                writable: true,
                pat: 2
            }],
            active: Vec::new(),
        };
        let unmap = Bind {
            object: None,
            address: 0x11000,
            length: 8192,
            op: 1,
            mapping: None,
            userptr: None,
        };
        let mapped = state.prepare(&[unmap], true).unwrap();
        assert_eq!(
            mapped
                .iter()
                .map(|m| (m.va, m.offset, m.length))
                .collect::<Vec<_>>(),
            [(0x10000, 0, 4096), (0x13000, 12288, 4096)]
        );
        assert_eq!(
            state.mappings.len(),
            1,
            "preparation mutated the published VM"
        );
        drop(mapped);
        let replace = Bind {
            object: None,
            address: 0x11000,
            length: 8192,
            op: 0,
            mapping: Some(VmMapping {
                object: None,
                va: 0x11000,
                offset: 0,
                length: 8192,
                writable: true,
                pat: 0,
            }),
            userptr: None,
        };
        let mapped = state.prepare(&[replace], true).unwrap();
        assert_eq!(mapped.len(), 3);
        assert!(mapped[1].object.is_none());
        assert_eq!(mapped[2].offset, 12288);
        drop(mapped);
        let weak = Arc::downgrade(&gem.object(handle).unwrap());
        let all = Bind {
            object: Some(gem.object(handle).unwrap()),
            address: 0,
            length: 0,
            op: 3,
            mapping: None,
            userptr: None,
        };
        gem.close(handle).unwrap();
        let mapped = state.prepare(&[all], true).unwrap();
        assert!(mapped.is_empty());
        assert!(weak.upgrade().is_some());
        drop(state);
        assert!(weak.upgrade().is_none());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_xe",
        smoke_xe_vm_interval_split_replace_and_atomic_failure
    );
}
