//! Native Xe per-open VM/queue ABI over the owned GuC RCS0/BCS0 backend.
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_vm.c,
//! xe_exec_queue.c, xe_exec.c, xe_sync.c and xe_wait_user_fence.c.
use crate::{
    drm::syncobj::{self as so, SyncObjTable},
    intel_gpu_exec::ResidentBatch,
    intel_gpu_gem::{GemState, Placement},
    intel_gpu_render::DeviceInfo,
    intel_gpu_uapi::{put32, put64, u32_at, u64_at},
    intel_gpu_user::{UserBatch, UserContext},
    intel_gpu_xe_sync::Sync,
    intel_gpu_xe_uapi as abi,
    intel_gpu_xe_vm::{read, zero, Bind, Vm},
};
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

/// xe_exec_queue_device_get_max_priority: CAP_SYS_NICE in the initial user
/// namespace admits HIGH. No userspace queue can request GuC KMD_HIGH (0).
pub(crate) fn max_queue_priority() -> u64 {
    if narf_filesystem::caller_capable(23) {
        2
    } else {
        1
    }
}

/// Source Xe emits this KLV for all supported IPs. GuCBoot::stage_image
/// validates each profile's authenticated CSS firmware minimum, and its
/// scheduler/reload gates submission ABI major 1 before the live owner can
/// publish engines/epoch. UserStatus carries that 1.x ABI, not CSS 70.x.
/// The hint changes no owner-wide SLPC min/max or power profile.
pub(crate) fn low_latency_supported(info: &DeviceInfo) -> bool {
    info.platform.guc().is_some()
        && info
            .backend
            .as_ref()
            .and_then(|backend| backend.status())
            .is_some_and(|status| {
                status.epoch != 0
                    && status.platform == info.platform
                    && status.submission_version.0 == 1
                    && status.engines.iter().next().is_some()
            })
}

/// DRM_XE_EXEC_QUEUE_SET_PROPERTY_PXP_TYPE and enum drm_xe_pxp_session_type.
const PXP_TYPE: u32 = 2;
const PXP_TYPE_NONE: u64 = 0;
const PXP_TYPE_HWDRM: u64 = 1;
/// MAX_USER_EXTENSIONS of xe_bo.c::gem_create_user_extensions and
/// xe_exec_queue.c::__exec_queue_user_extensions (each defines it as 16).
const MAX_USER_EXTENSIONS: usize = 16;

/// xe_pxp_is_enabled(xe->pxp) is false on every NARF device: Linux enables
/// PXP only with CONFIG_INTEL_MEI_GSC_PROXY (xe_pxp_is_supported), and NARF
/// has no MEI GSC proxy component, so every protected request is -ENODEV.
fn pxp_disabled() -> FsError {
    FsError::NoDevice
}

/// xe_bo.c::gem_create_user_extensions over DRM_XE_GEM_CREATE_EXTENSION_
/// SET_PROPERTY chains, in its check order: the extension-count bound, the
/// user extension header (copy, pad, name), the set-property body (copy,
/// property, pad), then gem_create_set_pxp_type. The result is applied after
/// the object exists, as xe_gem_create_ioctl runs the chain after
/// xe_bo_create_user.
fn gem_create_extensions(user: &dyn IoctlContext, mut next: u64) -> Result<(), FsError> {
    let mut count = 0;
    while next != 0 {
        // `if (ext_number >= MAX_USER_EXTENSIONS) return -E2BIG;` comes
        // before copy_from_user, so the seventeenth extension is refused
        // without being read: its address, header and body never matter.
        if count >= MAX_USER_EXTENSIONS {
            return Err(FsError::ArgumentListTooLong);
        }
        let base = read(user, next, 16)?;
        // struct drm_xe_user_extension: name 8, pad 12.
        if u32_at(&base, 12) != 0 || u32_at(&base, 8) >= 1 {
            return Err(FsError::InvalidData);
        }
        // struct drm_xe_ext_set_property: property 16, pad 20, value 24.
        let ext = read(user, next, 48)?;
        if u32_at(&ext, 16) >= 1 || u32_at(&ext, 20) != 0 {
            return Err(FsError::InvalidData);
        }
        // gem_create_set_pxp_type, then xe_pxp_key_assign(NULL): -ENODEV.
        match u64_at(&ext, 24) {
            PXP_TYPE_NONE => {}
            PXP_TYPE_HWDRM => return Err(pxp_disabled()),
            _ => return Err(FsError::InvalidData),
        }
        next = u64_at(&base, 0);
        count += 1;
    }
    Ok(())
}

/// DRM_XE_EXEC_QUEUE_SET_PROPERTY_*: the indices of xe_exec_queue.c's
/// exec_queue_set_property_funcs, whose ARRAY_SIZE is QUEUE_PROPERTIES.
const PRIORITY: u32 = 0;
const TIMESLICE: u32 = 1;
const HANG_REPLAY_STATE: u32 = 3;
const MULTI_GROUP: u32 = 4;
const MULTI_QUEUE_PRIORITY: u32 = 5;
const QUEUE_PROPERTIES: u32 = 6;
/// XE_EXEC_QUEUE_PRIORITY_HIGH and XE_MULTI_QUEUE_PRIORITY_HIGH.
const PRIORITY_HIGH: u64 = 2;
/// xe_hw_engine.h XE_HW_ENGINE_TIMESLICE_MIN/MAX: the Kconfig.profile
/// defaults DRM_XE_TIMESLICE_MIN=1 and DRM_XE_TIMESLICE_MAX=10000000 (us).
/// hw_engine_init_early installs them as every class's
/// sched_props.timeslice_min/max, which NARF exposes no sysfs to retune, so
/// xe_exec_queue_get_prop_minmax yields them with or without CAP_SYS_NICE.
pub(crate) const TIMESLICE_MIN_US: u64 = 1;
pub(crate) const TIMESLICE_MAX_US: u64 = 10_000_000;

/// What an EXEC_QUEUE_CREATE extension chain configured.
struct QueueProperties {
    /// GuC priority: Xe LOW/NORMAL/HIGH map to 3/2/1.
    priority: u32,
    timeslice: u32,
    /// DRM_XE_EXEC_QUEUE_SET_HANG_REPLAY_STATE copied an LRC image.
    replay: Option<Vec<u8>>,
}

/// xe_lrc.c::xe_gt_lrc_hang_replay_size for a UAPI engine class. A VM_BIND
/// queue's xe_exec_queue_create_bind queue is a COPY-class queue.
fn hang_replay_size(class: u16, xe2: bool) -> usize {
    4096 * match class {
        0 if xe2 => 3,
        4 if xe2 => 2,
        0 | 4 => 13,
        _ => 1,
    }
}

/// xe_exec_queue.c::exec_queue_user_extensions, in its check order. Per
/// extension (__exec_queue_user_extensions): the MAX_USER_EXTENSIONS bound,
/// the 16-byte drm_xe_user_extension copy, its pad and name; then
/// exec_queue_user_ext_set_property: the 48-byte drm_xe_ext_set_property
/// copy, the property-index bound and its pad (reserved[] is not checked),
/// then the property's setter. Finally exec_queue_user_ext_check_final.
fn exec_queue_extensions(
    user: &dyn IoctlContext,
    mut next: u64,
    class: u16,
    xe2: bool,
) -> Result<QueueProperties, FsError> {
    let mut queue = QueueProperties {
        priority: 2,
        timeslice: 1000,
        replay: None,
    };
    let mut properties = 0u64;
    let mut ext_number = 0;
    while next != 0 {
        // `if (ext_number >= MAX_USER_EXTENSIONS) return -E2BIG;` before
        // copy_from_user. Linux keeps no visited set: a chain that revisits
        // an extension applies it again and ends at this bound.
        if ext_number >= MAX_USER_EXTENSIONS {
            return Err(FsError::ArgumentListTooLong);
        }
        ext_number += 1;
        // struct drm_xe_user_extension: next_extension 0, name 8, pad 12.
        // It is copied and refused on its own, before the property body.
        let header = read(user, next, 16)?;
        if u32_at(&header, 12) != 0 || u32_at(&header, 8) >= 1 {
            return Err(FsError::InvalidData);
        }
        // struct drm_xe_ext_set_property: property 16, pad 20, value 24.
        let ext = read(user, next, 48)?;
        let property = u32_at(&ext, 16);
        if property >= QUEUE_PROPERTIES || u32_at(&ext, 20) != 0 {
            return Err(FsError::InvalidData);
        }
        // `*properties |= BIT_ULL(idx)` precedes the setter. Its
        // exec_queue_user_ext_check concerns multi-queue secondaries, which
        // no NARF queue can become (MULTI_GROUP below never succeeds).
        properties |= 1 << property;
        let value = u64_at(&ext, 24);
        match property {
            // exec_queue_set_priority.
            PRIORITY => {
                if value > PRIORITY_HIGH {
                    return Err(FsError::InvalidData);
                }
                if value == PRIORITY_HIGH && max_queue_priority() < value {
                    return Err(FsError::OperationNotPermitted);
                }
                queue.priority = 3 - value as u32;
            }
            // exec_queue_set_timeslice: with the default
            // CONFIG_DRM_XE_ENABLE_SCHEDTIMEOUT_LIMIT=y the limit is always
            // enforced, by xe_hw_engine_timeout_in_range's inclusive u64
            // compare.
            TIMESLICE if (TIMESLICE_MIN_US..=TIMESLICE_MAX_US).contains(&value) => {
                queue.timeslice = value as u32
            }
            TIMESLICE => return Err(FsError::InvalidData),
            // xe_exec_queue.c::exec_queue_set_pxp_type: NONE is the
            // default; only HWDRM is a session type, and without an
            // enabled PXP (xe->pxp is NULL: no MEI GSC proxy, see
            // xe_pxp_is_supported) it is -ENODEV.
            PXP_TYPE if value == PXP_TYPE_NONE => {}
            PXP_TYPE if value != PXP_TYPE_HWDRM => return Err(FsError::InvalidData),
            PXP_TYPE => return Err(pxp_disabled()),
            // exec_queue_set_hang_replay_state: vmemdup_user of the class's
            // replay size, so an unreadable image is -EFAULT here.
            HANG_REPLAY_STATE => {
                let bytes = read(user, value, hang_replay_size(class, xe2))?;
                queue.replay = Some(bytes);
            }
            // exec_queue_set_multi_group opens with
            // `if (!xe_exec_queue_supports_multi_queue(q)) return -ENODEV;`
            // and every pinned graphics descriptor's
            // multi_queue_engine_class_mask is zero.
            MULTI_GROUP => return Err(FsError::NoDevice),
            // exec_queue_set_multi_queue_priority: a creation-time value
            // (q->xef is still NULL) is range-checked and stored.
            MULTI_QUEUE_PRIORITY if value > PRIORITY_HIGH => {
                return Err(FsError::InvalidData);
            }
            _ => {}
        }
        next = u64_at(&header, 0);
    }
    // exec_queue_user_ext_check_final: MULTI_QUEUE_PRIORITY applies only
    // to a multi-queue group queue.
    if properties & 1 << MULTI_QUEUE_PRIORITY != 0 && properties & 1 << MULTI_GROUP == 0 {
        return Err(FsError::InvalidData);
    }
    Ok(queue)
}

#[derive(Debug)]
struct Queue {
    vm: Arc<Vm>,
    context: Arc<UserContext>,
    bind: bool,
    dead: AtomicBool,
}
impl Queue {
    fn check(&self) -> Result<(), FsError> {
        self.vm.check()?;
        if self.dead.load(Ordering::Acquire) {
            Err(FsError::NotFound)
        } else {
            Ok(())
        }
    }
}
#[derive(Debug)]
struct Names {
    next_vm: u32,
    next_queue: u32,
    vms: BTreeMap<u32, Arc<Vm>>,
    queues: BTreeMap<u32, Arc<Queue>>,
}
#[derive(Debug)]
pub(crate) struct XeFile {
    names: IrqSafeSpinLock<Names>,
}
impl XeFile {
    pub const fn new() -> Self {
        Self {
            names: IrqSafeSpinLock::new(Names {
                next_vm: 1,
                next_queue: 1,
                vms: BTreeMap::new(),
                queues: BTreeMap::new(),
            }),
        }
    }
    fn vm(&self, id: u32) -> Result<Arc<Vm>, FsError> {
        self.names
            .lock()
            .vms
            .get(&id)
            .cloned()
            .ok_or(FsError::NotFound)
    }
    fn queue(&self, id: u32) -> Result<Arc<Queue>, FsError> {
        self.names
            .lock()
            .queues
            .get(&id)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    pub fn dispatch(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        address: u64,
        user: &dyn IoctlContext,
        gem: &GemState,
    ) -> Option<Result<u64, FsError>> {
        let nr = crate::drm_uapi::ioc_nr(cmd);
        if crate::drm_uapi::ioc_type(cmd) != b'd' as u32 || (nr != 9 && !(0x40..0xa0).contains(&nr))
        {
            return None;
        }
        Some(self.ioctl(info, cmd, address, user, gem).map(|_| 0))
    }
    fn ioctl(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        address: u64,
        user: &dyn IoctlContext,
        gem: &GemState,
    ) -> Result<(), FsError> {
        match cmd {
            abi::DEVICE_QUERY => crate::intel_gpu_xe_query::query(info, address, user),
            abi::GEM_CREATE => {
                let mut wire = read(user, address, 56)?;
                zero(&wire[34..56])?;
                let size = u64_at(&wire, 8);
                let placement = u32_at(&wire, 16);
                let flags = u32_at(&wire, 20);
                // Region bit 0 is system memory, bit 1 the published VRAM.
                let regions = if info.vram.is_some() { 3 } else { 1 };
                // SCANOUT (2) is admitted where a WC system object satisfies
                // it: the iGPU. Arc display is not supported. An integrated
                // Xe2/Xe3 function has no scanout (or FlatCCS) representation
                // on its headless profile; the Lunar Lake display-20 and Panther
                // Lake display-30 routes' display-preserving profiles take XE_BO_FLAG_SCANOUT
                // (xe_bo.c::xe_gem_create_ioctl) as a WC system object.
                let supported_flags = match info.platform {
                    _ if info.platform.is_headless_integrated() => {
                        if (info.platform.is_lnl() || info.platform.is_ptl())
                            && info
                                .backend
                                .as_ref()
                                .is_some_and(|backend| backend.display_preserving())
                        {
                            2
                        } else {
                            0
                        }
                    }
                    crate::intel_gpu_gt::GtPlatform::Battlemage => {
                        8 | if info.vram.is_some() { 4 } else { 0 }
                    }
                    crate::intel_gpu_gt::GtPlatform::Integrated(_)
                    | crate::intel_gpu_gt::GtPlatform::Gen12(_) => 2,
                    crate::intel_gpu_gt::GtPlatform::Alchemist => {
                        if info.vram.is_some() {
                            4
                        } else {
                            0
                        }
                    }
                };
                // xe_gem_create_ioctl's EINVAL classes, then refused features.
                if size == 0
                    || size % 4096 != 0
                    || placement == 0
                    || placement & !regions != 0
                    || flags & !supported_flags != 0
                    || (flags & 4 != 0 && placement & 2 == 0)
                {
                    return Err(FsError::InvalidData);
                }
                let caching = u16::from_le_bytes(wire[32..34].try_into().unwrap());
                // VRAM needs WC, and scanout is never coherent with WB.
                if caching == 0
                    || caching > 2
                    || (placement & 2 != 0 && caching != 2)
                    || (flags & 2 != 0 && caching == 1)
                {
                    return Err(FsError::InvalidData);
                }
                // xe_ttm_tt_create: dGPU system memory is always WB (PCIe
                // snoops); an iGPU WC object's pages are write-combining.
                let wc = caching == 2 && !info.platform.is_discrete();
                // Read the extension chain before any lock; its verdict
                // applies once the object exists, as xe_gem_create_ioctl
                // runs gem_create_user_extensions after xe_bo_create_user.
                let extensions = gem_create_extensions(user, u64_at(&wire, 0));
                // Serialize VM removal through allocation/copyout/publication.
                let names = self.names.lock();
                let vm = if u32_at(&wire, 24) != 0 {
                    Some(
                        names
                            .vms
                            .get(&u32_at(&wire, 24))
                            .cloned()
                            .ok_or(FsError::NotFound)?,
                    )
                } else {
                    None
                };
                if let Some(vm) = &vm {
                    vm.check()?;
                }
                let memory = match info.vram.as_ref().filter(|_| placement & 2 != 0) {
                    Some(vram) => Placement::Vram(vram, placement & 1 != 0),
                    None if wc => Placement::SystemWc,
                    None => Placement::System,
                };
                let handle = gem.create_placed(
                    size,
                    vm.as_ref().map(|vm| vm.identity),
                    memory,
                    |handle, _| {
                        // A refused extension drops the new object unpublished.
                        extensions?;
                        put32(&mut wire, 28, handle);
                        user.write(address, &wire)
                    },
                )?;
                if flags & 2 != 0 {
                    // XE_BO_FLAG_SCANOUT; ADDFB may also set it later.
                    if let Ok(object) = gem.object(handle) {
                        object.mark_scanout();
                    }
                }
                Ok(())
            }
            abi::GEM_MMAP_OFFSET => {
                let mut wire = read(user, address, 40)?;
                zero(&wire[..8])?;
                zero(&wire[12..16])?;
                zero(&wire[24..40])?;
                let offset = gem.mmap_offset(u32_at(&wire, 8))?;
                put64(&mut wire, 16, offset);
                user.write(address, &wire)
            }
            crate::intel_gpu_uapi::GEM_CLOSE => {
                let wire = read(user, address, 8)?;
                zero(&wire[4..8])?;
                gem.close(u32_at(&wire, 0))
            }
            abi::VM_CREATE => {
                let mut wire = read(user, address, 32)?;
                zero(&wire[..8])?;
                zero(&wire[16..32])?;
                let flags = u32_at(&wire, 8);
                if flags & !7 != 0 || flags & 4 != 0 && flags & 2 == 0 {
                    return Err(FsError::InvalidData);
                }
                if flags & 6 != 0 {
                    return Err(FsError::NotImplemented);
                }
                let mut names = self.names.lock();
                if names.vms.len() >= 64 {
                    return Err(FsError::OutOfMemory);
                }
                let id = names.next_vm;
                let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
                let vm = Vm::new(
                    flags & 1 != 0 || info.platform == crate::intel_gpu_gt::GtPlatform::Battlemage,
                )?;
                put32(&mut wire, 12, id);
                user.write(address, &wire)?;
                names.vms.insert(id, vm);
                names.next_vm = next;
                Ok(())
            }
            abi::VM_DESTROY => {
                let wire = read(user, address, 24)?;
                zero(&wire[4..24])?;
                let mut names = self.names.lock();
                let id = u32_at(&wire, 0);
                let vm = names.vms.get(&id).ok_or(FsError::NotFound)?;
                if names.queues.values().any(|q| Arc::ptr_eq(&q.vm, vm)) {
                    return Err(FsError::Busy);
                }
                let vm = names.vms.remove(&id).expect("retained VM");
                vm.dead.store(true, Ordering::Release);
                Ok(())
            }
            abi::EXEC_QUEUE_CREATE => self.create_queue(info, address, user),
            abi::EXEC_QUEUE_DESTROY => {
                let wire = read(user, address, 24)?;
                zero(&wire[4..24])?;
                let queue = self
                    .names
                    .lock()
                    .queues
                    .remove(&u32_at(&wire, 0))
                    .ok_or(FsError::NotFound)?;
                queue.dead.store(true, Ordering::Release);
                queue.context.request_ban();
                Ok(())
            }
            abi::EXEC_QUEUE_GET_PROPERTY => {
                let wire = read(user, address, 40)?;
                zero(&wire[..8])?;
                zero(&wire[24..40])?;
                if u32_at(&wire, 12) != 0 {
                    return Err(FsError::InvalidData);
                }
                let queue = self.queue(u32_at(&wire, 8))?;
                user.write(
                    address.checked_add(16).ok_or(FsError::BadAddress)?,
                    &u64::from(queue.context.banned()).to_le_bytes(),
                )
            }
            abi::VM_BIND | abi::EXEC | abi::WAIT_USER_FENCE => Err(FsError::WouldBlock),
            abi::OBSERVATION => Err(FsError::NotImplemented),
            _ => Err(FsError::InvalidData),
        }
    }
    fn create_queue(
        &self,
        info: &DeviceInfo,
        address: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        if !info.submission_ready() {
            return Err(FsError::NoDevice);
        }
        let mut wire = read(user, address, 48)?;
        let flags = u32_at(&wire, 16);
        if flags & !abi::EXEC_QUEUE_LOW_LATENCY_HINT != 0 {
            return Err(FsError::InvalidData);
        }
        let low_latency = flags & abi::EXEC_QUEUE_LOW_LATENCY_HINT != 0;
        if low_latency && !low_latency_supported(info) {
            return Err(FsError::Unsupported);
        }
        zero(&wire[32..48])?;
        let width = u16::from_le_bytes(wire[8..10].try_into().unwrap());
        let count = u16::from_le_bytes(wire[10..12].try_into().unwrap());
        // xe_exec_queue.c bounds the copied placement matrix to nine entries.
        // At most four same-class lanes and nine copied matrix entries.
        if !(1..=4).contains(&width) || count == 0 || u32::from(width) * u32::from(count) > 9 {
            return Err(FsError::InvalidData);
        }
        let instances = read(
            user,
            u64_at(&wire, 24),
            usize::from(width) * usize::from(count) * 8,
        )?;
        let instance = &instances[..8];
        zero(&instance[6..8])?; // MBZ pad; the logical instance may be COPY1.
        let class = u16::from_le_bytes(instance[..2].try_into().unwrap());
        let logical = u16::from_le_bytes(instance[2..4].try_into().unwrap());
        let gt_id = u16::from_le_bytes(instance[4..6].try_into().unwrap());
        // Only a GT's published (fused-in) engines are addressable: GT0's,
        // and GT1's VCS/VECS once the standalone media GT is published.
        let present = info
            .backend
            .as_ref()
            .and_then(|b| b.status())
            .map_or_else(Default::default, |status| status.engines);
        let media = info.backend.as_ref().and_then(|b| b.media_gt());
        let gt_engines = |gt: u16| match gt {
            0 => Some(present),
            1 => media.map(|media| media.engines),
            _ => None,
        };
        // xe_exec_queue_create_ioctl: xe_device_get_gt(eci[0].gt_id) refuses
        // an unknown GT before any class, VM or placement handling.
        let gt_present = gt_engines(gt_id).ok_or(FsError::InvalidData)?;
        if class == 5 && (logical != 0 || count != 1 || width != 1) {
            return Err(FsError::InvalidData);
        }
        // Linux's VM_BIND hint reaches a real GuC bind engine. This ABI's
        // bind queues perform software page-table transactions, so there is
        // no hardware context on which to publish the requested policy.
        if class == 5 && low_latency {
            return Err(FsError::Unsupported);
        }
        let mut placements = crate::intel_gpu_engine::EngineSet::default();
        if class != 5 {
            let mut engines = alloc::vec::Vec::new();
            for instance in instances.chunks_exact(8) {
                zero(&instance[6..8])?;
                let candidate = u16::from_le_bytes(instance[..2].try_into().unwrap());
                let logical = u16::from_le_bytes(instance[2..4].try_into().unwrap());
                let candidate_gt = u16::from_le_bytes(instance[4..6].try_into().unwrap());
                // calc_validate_logical_mask: xe_hw_engine_lookup on the
                // entry's own GT, then the same-GT and same-class checks.
                let engine = gt_engines(candidate_gt)
                    .and_then(|set| set.from_class_instance(candidate, logical))
                    .ok_or(FsError::InvalidData)?;
                if candidate_gt != gt_id || candidate != class {
                    return Err(FsError::InvalidData);
                }
                engines.push(engine);
            }
            placements = crate::intel_gpu_engine::EngineSet::of(&engines);
        }
        // calc_validate_logical_mask's parallel checks, like the VM lookup
        // below, precede xe_exec_queue_create and so the extension chain.
        let lanes = if width > 1 {
            if !matches!(class, 1..=4) {
                return Err(FsError::InvalidData);
            }
            let mut lanes =
                alloc::vec![crate::intel_gpu_engine::EngineSet::default();usize::from(width)];
            let mut rows = BTreeSet::new();
            for row in instances.chunks_exact(usize::from(width) * 8) {
                let first = u16::from_le_bytes(row[2..4].try_into().unwrap());
                if !rows.insert(first) {
                    return Err(FsError::InvalidData);
                }
                for (index, instance) in row.chunks_exact(8).enumerate() {
                    let next = u16::from_le_bytes(instance[2..4].try_into().unwrap());
                    if first.checked_add(index as u16) != Some(next) {
                        return Err(FsError::InvalidData);
                    }
                    let engine = gt_present
                        .from_class_instance(class, next)
                        .ok_or(FsError::InvalidData)?;
                    lanes[index] = crate::intel_gpu_engine::EngineSet::from_bits(
                        lanes[index].bits()
                            | crate::intel_gpu_engine::EngineSet::of(&[engine]).bits(),
                    );
                }
            }
            Some(lanes)
        } else {
            None
        };
        // xe_exec_queue_create_ioctl: an unknown VM, or a closed or banned
        // one, is -ENOENT before xe_exec_queue_create(_bind) runs the
        // extensions. Publication repeats the lookup under the name lock.
        self.vm(u32_at(&wire, 12))?.check()?;
        let QueueProperties {
            priority,
            timeslice,
            replay,
        } = exec_queue_extensions(user, u64_at(&wire, 0), class, info.platform.is_xe2())?;
        let context = match lanes {
            Some(lanes) => UserContext::for_parallel(lanes)?,
            None if class == 5 => UserContext::new(),
            None => UserContext::for_placements(placements)?,
        };
        if let Some(replay) = &replay {
            context.init_hang_replay(replay)?;
        }
        context.configure_schedule(priority, timeslice)?;
        if low_latency {
            context.configure_low_latency()?;
        }
        let mut names = self.names.lock();
        let vm = names
            .vms
            .get(&u32_at(&wire, 12))
            .cloned()
            .ok_or(FsError::NotFound)?;
        vm.check()?;
        if names.queues.len() >= 64 {
            return Err(FsError::OutOfMemory);
        }
        let id = names.next_queue;
        let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
        let queue = Arc::new(Queue {
            vm,
            context,
            bind: class == 5,
            dead: AtomicBool::new(false),
        });
        // Revalidate the current creator after all extension copies and VM
        // preparation, immediately before publishing a name. Like Linux,
        // the resulting immutable queue retains its configured priority;
        // EXEC does not reauthorize or silently demote a live queue.
        if priority == 1 && max_queue_priority() < 2 {
            return Err(FsError::OperationNotPermitted);
        }
        if low_latency && !low_latency_supported(info) {
            return Err(FsError::NoDevice);
        }
        put32(&mut wire, 20, id);
        user.write(address, &wire)?;
        names.queues.insert(id, queue);
        names.next_queue = next;
        Ok(())
    }

    pub async fn dispatch_user(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        address: u64,
        user: &dyn IoctlContext,
        gem: &GemState,
        syncobjs: &Arc<IrqSafeSpinLock<SyncObjTable>>,
    ) -> Option<Result<u64, FsError>> {
        match cmd {
            abi::GEM_CREATE if info.platform.is_discrete() && info.vram.is_some() => {
                Some(self.create_vram(info, address, user, gem).await.map(|_| 0))
            }
            abi::DEVICE_QUERY => Some(
                crate::intel_gpu_xe_query::query_user(info, address, user)
                    .await
                    .map(|_| 0),
            ),
            abi::VM_BIND => Some(
                self.bind(info, address, user, gem, syncobjs)
                    .await
                    .map(|_| 0),
            ),
            abi::EXEC => Some(self.exec(info, address, user, syncobjs).await.map(|_| 0)),
            abi::WAIT_USER_FENCE => Some(self.wait_user(address, user).await.map(|_| 0)),
            abi::OBSERVATION => Some(self.observation(info, address, user, syncobjs).await),
            _ => self.dispatch(info, cmd, address, user, gem),
        }
    }

    /// xe_observation_ioctl: the copied-in param's extensions, then type and
    /// op routing. OA streams may name this file's exec queues.
    async fn observation(
        &self,
        info: &DeviceInfo,
        address: u64,
        user: &dyn IoctlContext,
        syncobjs: &Arc<IrqSafeSpinLock<SyncObjTable>>,
    ) -> Result<u64, FsError> {
        let wire = read(user, address, 32)?;
        if u64_at(&wire, 0) != 0 {
            return Err(FsError::InvalidData);
        }
        let op = u64_at(&wire, 16);
        match u64_at(&wire, 8) {
            0 => {
                let queues = |id: u32| {
                    self.names.lock().queues.get(&id).map(|queue| {
                        let context = &queue.context;
                        (
                            context.engine().xe_class(),
                            context.parallel().map_or(1, <[_]>::len),
                        )
                    })
                };
                crate::intel_gpu_oa::observation(
                    info.backend.clone(),
                    op,
                    u64_at(&wire, 24),
                    user,
                    &queues,
                    Some(syncobjs.clone()),
                )
                .await
            }
            1 if op != 0 => Err(FsError::InvalidData),
            1 => match info.backend.clone() {
                Some(backend) => crate::intel_gpu_eu_stall::open(backend, address, user).await,
                None => Err(FsError::NoDevice),
            },
            _ => Err(FsError::InvalidData),
        }
    }

    async fn create_vram(
        &self,
        info: &DeviceInfo,
        address: u64,
        user: &dyn IoctlContext,
        gem: &GemState,
    ) -> Result<(), FsError> {
        let mut wire = read(user, address, 56)?;
        zero(&wire[34..56])?;
        let size = u64_at(&wire, 8);
        let placement = u32_at(&wire, 16);
        let flags = u32_at(&wire, 20);
        let caching = u16::from_le_bytes(wire[32..34].try_into().unwrap());
        let supported_flags = if info.platform == crate::intel_gpu_gt::GtPlatform::Battlemage {
            4 | 8
        } else {
            4
        };
        let pool = info.vram.as_ref().ok_or(FsError::NoDevice)?;
        if size == 0 || size & 4095 != 0 || placement == 0 || placement & !3 != 0
            || flags & !supported_flags != 0 || (flags & 4 != 0 && placement & 2 == 0)
            || caching == 0 || caching > 2 || (placement & 2 != 0 && caching != 2)
            // xe_bo_create_locked_range: user objects with NEED64K VRAM
            // cannot be rounded behind the user's declared object extent.
            || (placement & 2 != 0 && size & (pool.page_size() - 1) != 0)
        {
            return Err(FsError::InvalidData);
        }
        // gem_create_user_extensions' verdict, applied once the object
        // exists (xe_gem_create_ioctl), never before a VM or allocation
        // refusal.
        let extensions = gem_create_extensions(user, u64_at(&wire, 0));
        let vm_id = u32_at(&wire, 24);
        let vm = if vm_id == 0 {
            None
        } else {
            Some(self.vm(vm_id)?)
        };
        if let Some(vm) = &vm {
            vm.check()?;
        }
        let owner = vm.as_ref().map(|vm| vm.identity);
        if placement & 2 == 0 {
            let names = self.names.lock();
            if let Some(vm) = &vm {
                vm.check()?;
            }
            gem.create_for_vm(size, owner, |handle, _| {
                extensions?;
                put32(&mut wire, 28, handle);
                user.write(address, &wire)
            })?;
            drop(names);
            return Ok(());
        }
        let pending = match gem.prepare_vram_class(
            size,
            owner,
            pool,
            flags & 4 != 0 || !pool.smallbar_enabled(),
        ) {
            Ok(pending) => pending,
            Err(FsError::OutOfMemory) if placement & 1 != 0 => {
                let names = self.names.lock();
                if let Some(vm) = &vm {
                    vm.check()?;
                }
                gem.create_for_vm(size, owner, |handle, _| {
                    extensions?;
                    put32(&mut wire, 28, handle);
                    user.write(address, &wire)
                })?;
                drop(names);
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        // The VRAM object exists: a refused extension drops it unpublished,
        // before any clear is submitted.
        extensions?;
        let backend = info.backend.as_ref().ok_or(FsError::NoDevice)?;
        let epoch = backend
            .status()
            .filter(|s| s.platform == info.platform && s.epoch != 0)
            .ok_or(FsError::NoDevice)?
            .epoch;
        let fence = backend.clear_vram(pending.object(), epoch).await?;
        fence
            .wait()
            .await
            .map_err(|_| crate::intel_gpu_user::io_error())?;
        if backend
            .status()
            .is_none_or(|s| s.platform != info.platform || s.epoch != epoch)
        {
            return Err(FsError::NoDevice);
        }
        if pool.smallbar_enabled() {
            let object = pending.object();
            let mut publication = gem.reserve_smallbar_publication(pending, &fence)?;
            // Faultable/reentrant output holds no GT/namespace/GEM guard.
            // The reserved ID is still absent from every public lookup.
            put32(&mut wire, 28, publication.handle);
            user.write(address, &wire)?;
            return backend
                .publish_vram(
                    epoch,
                    pool.clone(),
                    object,
                    fence,
                    Box::new(move |current| {
                        current()?;
                        let names = self.names.lock();
                        if let Some(vm) = &vm {
                            if names
                                .vms
                                .get(&vm_id)
                                .is_none_or(|live| !Arc::ptr_eq(live, vm))
                            {
                                return Err(FsError::NotFound);
                            }
                            vm.check()?;
                        }
                        publication.commit()?;
                        drop(names);
                        Ok(())
                    }),
                )
                .await;
        }
        // Nothing user-visible names this object before successful hardware
        // retirement. VM destruction during the wait cannot publish an orphan.
        let names = self.names.lock();
        if let Some(vm) = &vm {
            vm.check()?;
        }
        gem.publish_vram(pending, &fence, |handle, _| {
            put32(&mut wire, 28, handle);
            user.write(address, &wire)
        })?;
        drop(names);
        Ok(())
    }
    async fn bind(
        &self,
        info: &DeviceInfo,
        address: u64,
        user: &dyn IoctlContext,
        gem: &GemState,
        table: &IrqSafeSpinLock<SyncObjTable>,
    ) -> Result<(), FsError> {
        let wire = read(user, address, 136)?;
        zero(&wire[..8])?;
        zero(&wire[16..20])?;
        zero(&wire[104..108])?;
        zero(&wire[120..136])?;
        let vm = self.vm(u32_at(&wire, 8))?;
        let queue = if u32_at(&wire, 12) != 0 {
            let queue = self.queue(u32_at(&wire, 12))?;
            if !queue.bind || !Arc::ptr_eq(&queue.vm, &vm) {
                return Err(FsError::InvalidData);
            }
            Some(queue)
        } else {
            None
        };
        let count = u32_at(&wire, 20) as usize;
        if count > 4096 {
            return Err(FsError::InvalidData);
        }
        let vector = if count == 0 {
            alloc::vec::Vec::new()
        } else if count == 1 {
            wire[24..104].to_vec()
        } else {
            read(user, u64_at(&wire, 24), count * 80)?
        };
        let mut binds = alloc::vec::Vec::new();
        for op in vector.chunks_exact(80) {
            binds.push(Bind::read(op, &vm, gem, info.platform)?);
        }
        for bind in &mut binds {
            bind.pin(&vm, user)?;
        }
        let sync = Sync::read(user, u64_at(&wire, 112), u32_at(&wire, 108), table)?;
        if count == 0 && sync.user_fence.is_some() {
            return Err(FsError::NotImplemented);
        }
        let _order = match &queue {
            Some(queue) => Some(queue.context.serial.lock().await),
            None => None,
        };
        sync.wait().await;
        let mut state = vm.state.lock().await;
        vm.check()?;
        if let Some(queue) = &queue {
            queue.check()?;
        }
        let mappings = state.prepare(&binds, vm.scratch)?;
        state.retire().await?;
        vm.check()?;
        if let Some(queue) = &queue {
            queue.check()?;
        }
        // No await or fallible preparation after this user-fence report.
        // Concurrent exec must take the VM mutex before observing the mappings.
        if let Some((address, value)) = sync.user_fence {
            user.write_u64_release(address, value)?;
        }
        state.publish(mappings);
        // Adopt the new MAP_USERPTR bindings and forget the replaced ones
        // under the same VM lock, so exec always checks what it maps.
        let fresh = binds
            .iter_mut()
            .filter_map(|bind| bind.mirror.take())
            .collect();
        vm.adopt_userptrs(&state.mappings, fresh);
        sync.publish(so::stub());
        Ok(())
    }
    async fn exec(
        &self,
        info: &DeviceInfo,
        address: u64,
        user: &dyn IoctlContext,
        table: &IrqSafeSpinLock<SyncObjTable>,
    ) -> Result<(), FsError> {
        let wire = read(user, address, 56)?;
        zero(&wire[..8])?;
        zero(&wire[34..56])?;
        let count = u16::from_le_bytes(wire[32..34].try_into().unwrap());
        // xe_exec_ioctl order: queue lookup, VM queue, batch count against
        // the queue width, then reset status before any sync is parsed.
        let queue = self.queue(u32_at(&wire, 8))?;
        let parallel = queue.context.parallel();
        let width = parallel.map_or(1, <[_]>::len);
        if queue.bind || (count != 0 && usize::from(count) != width) {
            return Err(FsError::InvalidData);
        }
        // A hung or reset queue is banned: -ECANCELED (reset_status).
        let canceled = |error| {
            if queue.context.banned() {
                FsError::Canceled
            } else {
                error
            }
        };
        if queue.context.banned() {
            return Err(FsError::Canceled);
        }
        let sync = Sync::read(user, u64_at(&wire, 16), u32_at(&wire, 12), table)?;
        let addresses = if parallel.is_some() && count != 0 {
            let vector = read(user, u64_at(&wire, 24), width * 8)?;
            Some(
                vector
                    .chunks_exact(8)
                    .map(|word| u64_at(word, 0))
                    .collect::<alloc::vec::Vec<_>>(),
            )
        } else {
            None
        };
        let backend = info.backend.as_ref().ok_or(FsError::NoDevice)?;
        let _order = queue.context.serial.lock().await;
        sync.wait().await;
        if let Some(previous) = queue.context.last() {
            previous
                .wait()
                .await
                .map_err(|_| canceled(crate::intel_gpu_user::io_error()))?;
        }
        let mut state = queue.vm.state.lock().await;
        loop {
            queue.check()?;
            // xe_vm_userptr_pin: re-collect invalidated MAP_USERPTR bindings
            // before this job's private tables are built from the mappings.
            queue.vm.revalidate_userptrs(&mut state, user)?;
            let status = backend
                .status()
                .filter(|s| s.platform == info.platform)
                .ok_or(FsError::NoDevice)?;
            // A queue on the standalone media GT runs in GT1's own epoch;
            // GT0's epoch never admits it (and vice versa).
            let epoch = if crate::intel_gpu_gt::media::profile_eligible(status.platform)
                && queue.context.engine().is_media()
            {
                backend.media_gt().ok_or(FsError::NoDevice)?.epoch
            } else {
                status.epoch
            };
            queue.context.check_epoch(epoch).map_err(canceled)?;
            let resident = if parallel.is_some() {
                ResidentBatch::from_vm_parallel(
                    status.platform,
                    &state.mappings,
                    addresses.as_deref(),
                    width,
                    queue.vm.scratch,
                    sync.user_fence,
                )?
            } else {
                ResidentBatch::from_vm(
                    status.platform,
                    &state.mappings,
                    (count == 1).then_some(u64_at(&wire, 24)),
                    queue.vm.scratch,
                    sync.user_fence,
                )?
            };
            // __xe_vm_userptr_needs_repin at the point of no return: a binding
            // invalidated while the tables were built is re-collected and the
            // tables rebuilt (xe_exec_ioctl's -EAGAIN retry).
            if queue.vm.userptrs_stale() {
                continue;
            }
            match backend
                .submit(queue.context.clone(), UserBatch(resident))
                .await
            {
                Ok(fence) => {
                    state.active.retain(|fence| fence.result().is_none());
                    state.active.push(fence.clone());
                    sync.publish(so::from_drm_leaves(alloc::vec![fence]));
                    return Ok(());
                }
                Err(FsError::WouldBlock) => {
                    narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant())
                        .await
                }
                Err(error) => return Err(error),
            }
        }
    }
    async fn wait_user(&self, address: u64, user: &dyn IoctlContext) -> Result<(), FsError> {
        self.wait_user_clock(address, user, narf_time::monotonic_ns)
            .await
    }
    pub(crate) async fn wait_user_clock(
        &self,
        address: u64,
        user: &dyn IoctlContext,
        clock: impl Fn() -> u64,
    ) -> Result<(), FsError> {
        let wire = read(user, address, 72)?;
        zero(&wire[..8])?;
        zero(&wire[20..24])?;
        zero(&wire[52..72])?;
        let pointer = u64_at(&wire, 8);
        let op = u16::from_le_bytes(wire[16..18].try_into().unwrap());
        let flags = u16::from_le_bytes(wire[18..20].try_into().unwrap());
        if pointer & 7 != 0 || op > 5 || flags & !1 != 0 {
            return Err(FsError::InvalidData);
        }
        let queue = if u32_at(&wire, 48) != 0 {
            Some(self.queue(u32_at(&wire, 48))?)
        } else {
            None
        };
        let timeout = u64_at(&wire, 40) as i64;
        let start = clock();
        let deadline = (timeout >= 0).then(|| {
            if flags == 1 {
                timeout as u64
            } else {
                start.saturating_add(timeout as u64)
            }
        });
        let mask = u64_at(&wire, 32);
        let expected = u64_at(&wire, 24) & mask;
        let result = loop {
            let value = match user.read_u64_acquire(pointer) {
                Ok(value) => value & mask,
                Err(error) => break Err(error),
            };
            if match op {
                0 => value == expected,
                1 => value != expected,
                2 => value > expected,
                3 => value >= expected,
                4 => value < expected,
                _ => value <= expected,
            } {
                break Ok(());
            }
            if queue.as_ref().is_some_and(|q| q.context.banned()) {
                break Err(crate::intel_gpu_user::io_error());
            }
            if deadline.is_some_and(|end| clock() >= end) {
                break Err(FsError::TimedOut);
            }
            if timeout < 0 && user.restart_after(100_000) {
                break Err(FsError::WouldBlock);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        };
        if flags == 0 && timeout >= 0 {
            let remaining = (timeout as u64).saturating_sub(clock().saturating_sub(start));
            user.write(
                address.checked_add(40).ok_or(FsError::BadAddress)?,
                &remaining.to_le_bytes(),
            )?;
        }
        result
    }
}
