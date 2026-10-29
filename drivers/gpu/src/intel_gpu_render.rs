//! Intel render-node UAPI over per-open GEM/context/VM namespaces.
//!
//! Xe-LP and Xe-LPG share the i915 userspace wire ABI. Submission admission is
//! independent of display admission: a working panel is not an initialized GT.
//! Unsupported acceleration is reported as such, never as a completed job.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

use crate::intel_gpu::Generation;
use crate::intel_gpu_gem::GemState;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_hwconfig::HardwareConfig;
use crate::intel_gpu_uapi::{self as abi, put32, put64, u32_at, u64_at};

const MAX_COPY: usize = 1024 * 1024;
const MAX_QUERIES: usize = 64;
const MAX_CONTEXTS: usize = 64;
const MAX_VMS: usize = 64;
const MAX_EXTENSIONS: usize = 16;

/// A submission profile, deliberately separate from display generation gates.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SubmissionProfile {
    Gen12Execlists,
    XeLpgGuC,
    Unsupported,
}

impl SubmissionProfile {
    pub const fn for_generation(generation: Generation) -> Self {
        match generation {
            Generation::TigerLake | Generation::AlderLake => Self::Gen12Execlists,
            Generation::MeteorLake => Self::XeLpgGuC,
            Generation::PantherLake => Self::Unsupported,
        }
    }
}

/// Probe-owned facts. No topology, memory size or firmware version is guessed.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub device_id: u16,
    pub platform: GtPlatform,
    pub memory_bytes: u64,
    pub hwconfig: Option<Arc<HardwareConfig>>,
    pub topology: Option<Arc<crate::intel_gpu_topology::GtTopology>>,
}

impl DeviceInfo {
    pub fn for_card(card: u32) -> Option<Self> {
        let card = crate::drm_registry::card(card)?;
        if card.driver() != "intel-gpu" {
            return None;
        }
        let device_id = card.device_id();
        let platform = GtPlatform::from_pci(card.vendor_id(), device_id)?;
        Some(Self {
            device_id,
            platform,
            memory_bytes: narf_memory::frame::stats().total as u64 * 4096,
            hwconfig: card.intel_hwconfig(),
            topology: card.intel_topology(),
        })
    }

    /// No userspace engine is published until isolation, context setup,
    /// completion and reset/loss handling are installed by the GT owner.
    pub const fn submission_ready(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct Vm {
    _identity: u32,
}

#[derive(Clone, Debug)]
struct Context {
    vm: Arc<Vm>,
    no_error_capture: bool,
    bannable: bool,
    recoverable: bool,
    persistence: bool,
}

impl Context {
    fn new(vm: Arc<Vm>) -> Self {
        Self {
            vm,
            no_error_capture: false,
            bannable: true,
            recoverable: true,
            persistence: true,
        }
    }
}

#[derive(Debug)]
struct Namespaces {
    next_context: u32,
    next_vm: u32,
    contexts: BTreeMap<u32, Context>,
    vms: BTreeMap<u32, Arc<Vm>>,
}

impl Namespaces {
    fn initialize(&mut self) {
        self.contexts
            .entry(0)
            .or_insert_with(|| Context::new(Arc::new(Vm { _identity: 0 })));
    }

    fn parameter(&mut self, bytes: &mut [u8], set: bool) -> Result<(), FsError> {
        let id = u32_at(bytes, 0);
        let size = u32_at(bytes, 4);
        let param = u64_at(bytes, 8);
        let value = u64_at(bytes, 16);
        if size != 0 {
            return Err(FsError::InvalidData);
        }
        self.initialize();
        let context = self.contexts.get_mut(&id).ok_or(FsError::NotFound)?;
        match (param, set) {
            (3, false) => put64(bytes, 16, 1 << 48),
            (4 | 5 | 8 | 11, _) => {
                let target = match param {
                    4 => &mut context.no_error_capture,
                    5 => &mut context.bannable,
                    8 => &mut context.recoverable,
                    _ => &mut context.persistence,
                };
                if set {
                    if value > 1 {
                        return Err(FsError::InvalidData);
                    }
                    // Disabling banning requires authority this UAPI does not grant.
                    if param == 5 && value == 0 {
                        return Err(FsError::OperationNotPermitted);
                    }
                    *target = value != 0;
                } else {
                    put64(bytes, 16, u64::from(*target));
                }
            }
            (6, _) => {
                // Only normal priority is supported until a GT scheduler exists.
                if set && value != 0 {
                    return Err(FsError::InvalidData);
                }
                put64(bytes, 16, 0);
            }
            (9, true) => {
                let vm_id = u32::try_from(value).map_err(|_| FsError::NotFound)?;
                context.vm = self.vms.get(&vm_id).cloned().ok_or(FsError::NotFound)?;
            }
            (9, false) => {
                let vm = context.vm.clone();
                let existing = self
                    .vms
                    .iter()
                    .find(|(_, entry)| Arc::ptr_eq(entry, &vm))
                    .map(|(id, _)| *id);
                let id = if let Some(id) = existing {
                    id
                } else {
                    if self.vms.len() >= MAX_VMS {
                        return Err(FsError::OutOfMemory);
                    }
                    let id = self.next_vm;
                    self.next_vm = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
                    self.vms.insert(id, vm);
                    id
                };
                put64(bytes, 16, id as u64);
            }
            _ => return Err(FsError::InvalidData),
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct RenderFile {
    pub gem: GemState,
    namespaces: IrqSafeSpinLock<Namespaces>,
}

impl Default for RenderFile {
    fn default() -> Self {
        Self::new()
    }
}

impl RenderFile {
    pub const fn new() -> Self {
        Self {
            gem: GemState::new(),
            namespaces: IrqSafeSpinLock::new(Namespaces {
                next_context: 1,
                next_vm: 1,
                contexts: BTreeMap::new(),
                vms: BTreeMap::new(),
            }),
        }
    }

    pub(crate) fn dispatch_card(
        &self,
        card: u32,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        if crate::drm_registry::driver_name(card) != Some("intel-gpu") {
            return None;
        }
        let info = match DeviceInfo::for_card(card) {
            Some(info) => info,
            None => return Some(Err(FsError::NoDevice)),
        };
        self.dispatch(&info, cmd, arg, user)
    }

    /// `None` means a generic DRM command, not an error from an Intel ioctl.
    /// Once recognized, a malformed Intel command cannot fall through to KMS.
    pub fn dispatch(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Option<Result<u64, FsError>> {
        let nr = crate::drm_uapi::ioc_nr(cmd);
        if crate::drm_uapi::ioc_type(cmd) != b'd' as u32 {
            return None;
        }
        if nr != 9 && !(0x40..0x80).contains(&nr) {
            return None;
        }
        Some(self.ioctl(info, cmd, arg, user).map(|()| 0))
    }

    fn ioctl(
        &self,
        info: &DeviceInfo,
        cmd: u32,
        arg: u64,
        user: &dyn IoctlContext,
    ) -> Result<(), FsError> {
        match cmd {
            abi::GETPARAM => {
                let request = read(user, arg, 16)?;
                let value = getparam(info, u32_at(&request, 0))?;
                user.write(u64_at(&request, 8), &value.to_le_bytes())
            }
            abi::GEM_CREATE | abi::GEM_CREATE_EXT => {
                let mut request = read(user, arg, if cmd == abi::GEM_CREATE { 16 } else { 24 })?;
                if cmd == abi::GEM_CREATE_EXT {
                    if u32_at(&request, 12) != 0 {
                        return Err(FsError::InvalidData);
                    }
                    create_extensions(user, u64_at(&request, 16))?;
                }
                self.gem.create(u64_at(&request, 0), |handle, size| {
                    put64(&mut request, 0, size);
                    put32(&mut request, 8, handle);
                    user.write(arg, &request)
                })?;
                Ok(())
            }
            abi::GEM_CLOSE => {
                let request = read(user, arg, 8)?;
                if u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                self.gem.close(u32_at(&request, 0))
            }
            abi::GEM_PREAD | abi::GEM_PWRITE => {
                let request = read(user, arg, 32)?;
                if u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                let object = self.gem.object(u32_at(&request, 0))?;
                let offset = u64_at(&request, 8);
                let size =
                    usize::try_from(u64_at(&request, 16)).map_err(|_| FsError::InvalidData)?;
                object.range(offset, size)?;
                if size == 0 {
                    return Ok(());
                }
                let pointer = u64_at(&request, 24);
                pointer
                    .checked_add(size as u64)
                    .ok_or(FsError::BadAddress)?;
                let mut done = 0;
                // Bound temporary copies while accepting uploads larger than
                // one copy buffer. A later EFAULT may leave a written prefix,
                // as in the Linux pread/pwrite interface.
                while done < size {
                    let count = (size - done).min(16 * 1024);
                    if cmd == abi::GEM_PWRITE {
                        let data = read(user, pointer + done as u64, count)?;
                        object.write(offset + done as u64, &data)?;
                    } else {
                        let mut data = vec![0; count];
                        object.read(offset + done as u64, &mut data)?;
                        user.write(pointer + done as u64, &data)?;
                    }
                    done += count;
                }
                Ok(())
            }
            abi::GEM_MMAP_GTT | abi::GEM_MMAP_OFFSET => {
                let mut request = read(user, arg, if cmd == abi::GEM_MMAP_GTT { 16 } else { 32 })?;
                if u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                if cmd == abi::GEM_MMAP_OFFSET {
                    // System RAM mappings are WB in NARF on both architectures.
                    // Reject aliases with incompatible cache types, rather than
                    // accepting WC and returning a WB mapping silently.
                    if u64_at(&request, 16) != 2 || u64_at(&request, 24) != 0 {
                        return Err(FsError::InvalidData);
                    }
                } else {
                    return Err(FsError::NotImplemented);
                }
                let offset = self.gem.mmap_offset(u32_at(&request, 0))?;
                put64(&mut request, 8, offset);
                user.write(arg, &request)
            }
            abi::GEM_BUSY | abi::GEM_WAIT | abi::GEM_SET_DOMAIN | abi::GEM_SW_FINISH => {
                let size = match cmd {
                    abi::GEM_BUSY => 8,
                    abi::GEM_WAIT => 16,
                    abi::GEM_SET_DOMAIN => 12,
                    _ => 4,
                };
                let mut request = read(user, arg, size)?;
                self.gem.object(u32_at(&request, 0))?;
                if cmd == abi::GEM_WAIT && u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                if cmd == abi::GEM_SET_DOMAIN {
                    let reads = u32_at(&request, 4);
                    let write = u32_at(&request, 8);
                    if reads & !0xc1 != 0
                        || write & !0xc1 != 0
                        || write.count_ones() > 1
                        || (write != 0 && reads != write)
                    {
                        return Err(FsError::InvalidData);
                    }
                }
                if cmd == abi::GEM_BUSY {
                    put32(&mut request, 4, 0);
                    return user.write(arg, &request);
                }
                // There is no admitted userspace submitter yet: these objects
                // cannot have outstanding GPU work. Add fence waits with submit.
                Ok(())
            }
            abi::GEM_GET_TILING
            | abi::GEM_SET_TILING
            | abi::GEM_GET_CACHING
            | abi::GEM_SET_CACHING => {
                let size = if matches!(cmd, abi::GEM_GET_TILING | abi::GEM_SET_TILING) {
                    16
                } else {
                    8
                };
                let mut request = read(user, arg, size)?;
                self.gem.object(u32_at(&request, 0))?;
                match cmd {
                    abi::GEM_SET_TILING if u32_at(&request, 4) != 0 || u32_at(&request, 8) != 0 => {
                        return Err(FsError::InvalidData)
                    }
                    abi::GEM_SET_CACHING if u32_at(&request, 4) != 1 => {
                        return Err(FsError::InvalidData)
                    }
                    abi::GEM_GET_CACHING => put32(&mut request, 4, 1),
                    abi::GEM_GET_TILING | abi::GEM_SET_TILING => request[4..].fill(0),
                    _ => {}
                }
                if cmd == abi::GEM_SET_CACHING {
                    // This command is _IOW: a readable request does not need
                    // to be writable, unlike the GET/TILING reply structs.
                    return Ok(());
                }
                user.write(arg, &request)
            }
            abi::GEM_MADVISE => {
                let mut request = read(user, arg, 12)?;
                self.gem.object(u32_at(&request, 0))?;
                if u32_at(&request, 4) > 1 {
                    return Err(FsError::InvalidData);
                }
                // Retaining DONTNEED storage is allowed; no fabricated purge.
                put32(&mut request, 8, 1);
                user.write(arg, &request)
            }
            abi::GEM_GET_APERTURE => {
                // PPGTT VA width is not the physical GGTT aperture size.
                Err(FsError::NotImplemented)
            }
            abi::GEM_CONTEXT_CREATE | abi::GEM_CONTEXT_CREATE_EXT => {
                self.create_context(cmd, arg, user)
            }
            abi::GEM_CONTEXT_DESTROY => {
                let request = read(user, arg, 8)?;
                let id = u32_at(&request, 0);
                if id == 0 || u32_at(&request, 4) != 0 {
                    return Err(FsError::InvalidData);
                }
                self.namespaces
                    .lock()
                    .contexts
                    .remove(&id)
                    .ok_or(FsError::NotFound)?;
                Ok(())
            }
            abi::GEM_CONTEXT_GETPARAM | abi::GEM_CONTEXT_SETPARAM => {
                let mut request = read(user, arg, 24)?;
                self.namespaces
                    .lock()
                    .parameter(&mut request, cmd == abi::GEM_CONTEXT_SETPARAM)?;
                user.write(arg, &request)
            }
            abi::GEM_VM_CREATE | abi::GEM_VM_DESTROY => {
                let mut request = read(user, arg, 16)?;
                if u64_at(&request, 0) != 0 || u32_at(&request, 8) != 0 {
                    return Err(FsError::InvalidData);
                }
                let mut namespaces = self.namespaces.lock();
                if cmd == abi::GEM_VM_DESTROY {
                    namespaces
                        .vms
                        .remove(&u32_at(&request, 12))
                        .ok_or(FsError::NotFound)?;
                } else {
                    if namespaces.vms.len() >= MAX_VMS {
                        return Err(FsError::OutOfMemory);
                    }
                    let id = namespaces.next_vm;
                    let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
                    put32(&mut request, 12, id);
                    user.write(arg, &request)?;
                    namespaces.vms.insert(id, Arc::new(Vm { _identity: id }));
                    namespaces.next_vm = next;
                }
                Ok(())
            }
            abi::GET_RESET_STATS => {
                let mut request = read(user, arg, 24)?;
                if u32_at(&request, 4) != 0 || u32_at(&request, 20) != 0 {
                    return Err(FsError::InvalidData);
                }
                let mut namespaces = self.namespaces.lock();
                namespaces.initialize();
                if !namespaces.contexts.contains_key(&u32_at(&request, 0)) {
                    return Err(FsError::NotFound);
                }
                request[8..20].fill(0);
                user.write(arg, &request)
            }
            abi::QUERY => query(info, arg, user),
            abi::GEM_THROTTLE => Ok(()),
            abi::GEM_EXECBUFFER2 | abi::GEM_EXECBUFFER2_WR => {
                let request = crate::intel_gpu_exec::ExecRequest::read(user, arg, &self.gem)?;
                let mut namespaces = self.namespaces.lock();
                namespaces.initialize();
                if !namespaces.contexts.contains_key(&request.context_id) {
                    return Err(FsError::NotFound);
                }
                // A validated residency plan does not initialize the GT or
                // grant privileged execution. Keep it private until a backend
                // owns context setup, cache flushes, completion and reset.
                Err(FsError::NotImplemented)
            }
            _ => Err(FsError::InvalidData),
        }
    }

    fn create_context(&self, cmd: u32, arg: u64, user: &dyn IoctlContext) -> Result<(), FsError> {
        let mut request = read(
            user,
            arg,
            if cmd == abi::GEM_CONTEXT_CREATE {
                8
            } else {
                16
            },
        )?;
        let flags = u32_at(&request, 4);
        if (cmd == abi::GEM_CONTEXT_CREATE && flags != 0) || flags & !3 != 0 {
            return Err(FsError::InvalidData);
        }
        let mut params = Vec::new();
        if cmd == abi::GEM_CONTEXT_CREATE_EXT && flags & 1 != 0 {
            extensions(user, u64_at(&request, 8), |address, name| {
                if name != 0 {
                    return Err(FsError::InvalidData);
                }
                let ext = read(user, address, 56)?;
                let param = ext[32..].to_vec();
                if u32_at(&param, 0) != 0 {
                    return Err(FsError::InvalidData);
                }
                params.push(param);
                Ok(())
            })?;
        }
        let mut namespaces = self.namespaces.lock();
        namespaces.initialize();
        if namespaces.contexts.len() >= MAX_CONTEXTS {
            return Err(FsError::OutOfMemory);
        }
        let id = namespaces.next_context;
        let next = id.checked_add(1).ok_or(FsError::OutOfMemory)?;
        namespaces
            .contexts
            .insert(id, Context::new(Arc::new(Vm { _identity: id })));
        let result = (|| {
            for mut param in params {
                put32(&mut param, 0, id);
                namespaces.parameter(&mut param, true)?;
            }
            put32(&mut request, 0, id);
            user.write(arg, &request)
        })();
        if result.is_err() {
            namespaces.contexts.remove(&id);
        } else {
            namespaces.next_context = next;
        }
        result
    }
}

/// Synchronous kernel callers use the same guarded copy seam as other DRM
/// ioctls. Userspace FileOps::ioctl_user supplies its fault-contained context.
pub(crate) struct GuardedIoctl;
impl IoctlContext for GuardedIoctl {
    fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
        // SAFETY: called only in the ioctl trap context, like the shared bridge.
        let bytes =
            unsafe { crate::drm_ioctl_bridge::copy_in(address as usize, destination.len())? };
        destination.copy_from_slice(&bytes);
        Ok(())
    }
    fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
        // SAFETY: same syscall/address-space contract as read().
        unsafe { crate::drm_ioctl_bridge::copy_out(address as usize, source) }
    }
    fn nonblocking(&self) -> bool {
        false
    }
}

fn read(user: &dyn IoctlContext, address: u64, size: usize) -> Result<Vec<u8>, FsError> {
    if size > MAX_COPY {
        return Err(FsError::InvalidData);
    }
    let mut bytes = vec![0; size];
    user.read(address, &mut bytes)?;
    Ok(bytes)
}

fn extensions(
    user: &dyn IoctlContext,
    mut address: u64,
    mut consume: impl FnMut(u64, u32) -> Result<(), FsError>,
) -> Result<(), FsError> {
    let mut seen = [0; MAX_EXTENSIONS];
    let mut count = 0;
    while address != 0 {
        if count == MAX_EXTENSIONS || seen[..count].contains(&address) {
            return Err(FsError::InvalidData);
        }
        seen[count] = address;
        count += 1;
        let extension = read(user, address, 32)?;
        if extension[12..].iter().any(|byte| *byte != 0) {
            return Err(FsError::InvalidData);
        }
        consume(address, u32_at(&extension, 8))?;
        address = u64_at(&extension, 0);
    }
    Ok(())
}

fn create_extensions(user: &dyn IoctlContext, address: u64) -> Result<(), FsError> {
    extensions(user, address, |address, name| {
        if name != 0 {
            return Err(FsError::InvalidData);
        }
        let extension = read(user, address, 48)?;
        if u32_at(&extension, 32) != 0 || u32_at(&extension, 36) != 1 {
            return Err(FsError::InvalidData);
        }
        let region = read(user, u64_at(&extension, 40), 4)?;
        if region != [0, 0, 0, 0] {
            return Err(FsError::InvalidData);
        }
        Ok(())
    })
}

fn getparam(info: &DeviceInfo, param: u32) -> Result<i32, FsError> {
    Ok(match param {
        4 => info.device_id as i32,
        5 => 1,  // GEM storage is available independently of acceleration.
        18 => 0, // no admitted userspace address-space backend yet
        19 => 1, // GEM_WAIT supports the timeout wire request
        30 => 0, // legacy GEM_MMAP returns a CPU VA: not supported
        40 => 4, // MMAP_OFFSET, WB only
        // Explicitly absent features. Never claim unimplemented submission,
        // reset, media, sync-file, cache domains, or context isolation support.
        1..=3 | 6..=17 | 20..=29 | 31 | 35..=39 | 41..=50 | 52..=59 => 0,
        _ => return Err(FsError::InvalidData),
    })
}

fn query(info: &DeviceInfo, arg: u64, user: &dyn IoctlContext) -> Result<(), FsError> {
    let request = read(user, arg, 16)?;
    let count = u32_at(&request, 0) as usize;
    if count > MAX_QUERIES || u32_at(&request, 4) != 0 {
        return Err(FsError::InvalidData);
    }
    if count == 0 {
        return Ok(());
    }
    let pointer = u64_at(&request, 8);
    let items = read(user, pointer, count * 24)?;
    for (i, item) in items.chunks_exact(24).enumerate() {
        let id = u64_at(item, 0);
        let capacity = u32_at(item, 8) as i32;
        let flags = u32_at(item, 12);
        let result = (|| {
            if flags != 0 || capacity < 0 {
                return Err(FsError::InvalidData);
            }
            let reply: Cow<'_, [u8]> = match id {
                abi::QUERY_ENGINES => Cow::Owned(vec![0; 16]), // no userspace queues admitted
                abi::QUERY_MEMORY_REGIONS if info.memory_bytes != 0 => {
                    let mut reply = vec![0; 104]; // header16 + memory_region_info88
                    put32(&mut reply, 0, 1);
                    put64(&mut reply, 24, info.memory_bytes);
                    put64(&mut reply, 32, info.memory_bytes);
                    Cow::Owned(reply)
                }
                abi::QUERY_HWCONFIG => {
                    Cow::Borrowed(info.hwconfig.as_ref().ok_or(FsError::NoDevice)?.as_bytes())
                }
                abi::QUERY_TOPOLOGY | abi::QUERY_GEOMETRY_SUBSLICES => {
                    let topology = info.topology.as_ref().ok_or(FsError::NoDevice)?;
                    if topology.platform() != info.platform
                        || (id == abi::QUERY_GEOMETRY_SUBSLICES && !topology.has_render())
                    {
                        return Err(FsError::NoDevice);
                    }
                    Cow::Owned(topology.i915_bytes(id == abi::QUERY_GEOMETRY_SUBSLICES))
                }
                // Linux reports the GuC scheduling interface, not the loaded
                // firmware's release. No submission interface is installed yet.
                abi::QUERY_GUC_SUBMISSION_VERSION => return Err(FsError::NoDevice),
                _ => return Err(FsError::InvalidData),
            };
            let required = reply.len() as i32;
            if capacity != 0 {
                if capacity < required {
                    return Err(FsError::InvalidData);
                }
                if matches!(id, abi::QUERY_TOPOLOGY | abi::QUERY_GEOMETRY_SUBSLICES) {
                    // i915_query.c::copy_query_item requires a readable header
                    // before replacing it, even though its contents are ignored.
                    read(user, u64_at(item, 16), 16)?;
                }
                user.write(u64_at(item, 16), &reply)?;
            }
            Ok(required)
        })();
        let length = match result {
            Ok(size) => size,
            Err(FsError::BadAddress) => -14,
            Err(FsError::NoDevice) => -19,
            Err(_) => -22,
        };
        // Only length is an output field. Preserve item flags, pointer and id.
        let output = pointer
            .checked_add(i as u64 * 24 + 8)
            .ok_or(FsError::BadAddress)?;
        user.write(output, &length.to_le_bytes())?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct User {
        bytes: IrqSafeSpinLock<Vec<u8>>,
        fail_write: IrqSafeSpinLock<Option<u64>>,
        fail_read: IrqSafeSpinLock<Option<u64>>,
    }
    impl User {
        fn new() -> Self {
            Self {
                bytes: IrqSafeSpinLock::new(vec![0; 32768]),
                fail_write: IrqSafeSpinLock::new(None),
                fail_read: IrqSafeSpinLock::new(None),
            }
        }
        fn store(&self, address: u64, data: &[u8]) {
            self.write(address, data).expect("fixture store");
        }
        fn load(&self, address: u64, len: usize) -> Vec<u8> {
            read(self, address, len).expect("fixture load")
        }
    }
    impl IoctlContext for User {
        fn read(&self, address: u64, destination: &mut [u8]) -> Result<(), FsError> {
            if *self.fail_read.lock() == Some(address) {
                return Err(FsError::BadAddress);
            }
            let memory = self.bytes.lock();
            let end = address
                .checked_add(destination.len() as u64)
                .ok_or(FsError::BadAddress)?;
            if address == 0 || end > memory.len() as u64 {
                return Err(FsError::BadAddress);
            }
            destination.copy_from_slice(&memory[address as usize..end as usize]);
            Ok(())
        }
        fn write(&self, address: u64, source: &[u8]) -> Result<(), FsError> {
            if *self.fail_write.lock() == Some(address) {
                return Err(FsError::BadAddress);
            }
            let mut memory = self.bytes.lock();
            let end = address
                .checked_add(source.len() as u64)
                .ok_or(FsError::BadAddress)?;
            if address == 0 || end > memory.len() as u64 {
                return Err(FsError::BadAddress);
            }
            memory[address as usize..end as usize].copy_from_slice(source);
            Ok(())
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }
    fn info(generation: Generation) -> DeviceInfo {
        DeviceInfo {
            device_id: 0x7d55,
            platform: GtPlatform::Integrated(generation),
            memory_bytes: 0x8000_0000,
            hwconfig: None,
            topology: None,
        }
    }
    fn invoke(file: &RenderFile, user: &User, cmd: u32) -> Result<u64, FsError> {
        file.dispatch(&info(Generation::MeteorLake), cmd, 64, user)
            .expect("Intel command")
    }
    fn check(run: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
        match run() {
            Ok(()) => TestResult::Pass,
            Err(why) => TestResult::Fail(why),
        }
    }

    /// Exercise the actual primary/render file dispatchers against one card's
    /// immutable snapshot, including when its firmware owner has been dropped.
    pub(crate) fn check_card_hwconfig(
        card: u32,
        expected: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        use narf_filesystem::DirOps;
        for name in [
            alloc::format!("card{card}"),
            alloc::format!("renderD{}", card + 128),
        ] {
            let file = crate::drm_devfs_bridge::DriDir
                .lookup(&name)
                .ok_or("DRM node")?;
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 5);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 120];
            for (item, id) in items.chunks_exact_mut(24).zip([5, 7, 2, 1, 4]) {
                put64(item, 0, id);
            }
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node query")?;
            let lengths = user.load(256, 120);
            if u32_at(&lengths, 8) as i32 != expected.map_or(-19, |bytes| bytes.len() as i32)
                || u32_at(&lengths, 32) as i32 != -19 // no GuC submission interface
                || u32_at(&lengths, 56) != 16 // no admitted engines
                || u32_at(&lengths, 80) as i32 != -19 // no observed topology
                || u32_at(&lengths, 104) != 104
            // system RAM only
            {
                return Err("card query availability/length");
            }
            if let Some(bytes) = expected {
                put32(&mut items, 8, bytes.len() as u32 + 8);
                put64(&mut items, 16, 1024);
                put32(&mut items, 56, 16);
                put64(&mut items, 64, 2048);
                put32(&mut items, 104, 104);
                put64(&mut items, 112, 4096);
                user.store(256, &items);
                user.store(1024 + bytes.len() as u64, &[0xaa; 8]);
                narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                    .map_err(|_| "node data query")?;
                if user.load(1024, bytes.len()) != bytes
                    || user.load(1024 + bytes.len() as u64, 8) != [0xaa; 8]
                    || user.load(2048, 16) != [0; 16]
                {
                    return Err("exact HWCONFIG bytes/extent or invented engine");
                }
                let memory = user.load(4096, 104);
                if u32_at(&memory, 0) != 1 || u32_at(&memory, 16) != 0 {
                    return Err("system memory misreported as VRAM");
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "kernel-test")]
    pub(crate) fn check_card_topology(
        card: u32,
        expected: Option<&[u8]>,
        geometry: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        use narf_filesystem::DirOps;
        for name in [
            alloc::format!("card{card}"),
            alloc::format!("renderD{}", card + 128),
        ] {
            let file = crate::drm_devfs_bridge::DriDir
                .lookup(&name)
                .ok_or("DRM topology node")?;
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 3);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 72];
            for (item, id) in items.chunks_exact_mut(24).zip([1, 6, 2]) {
                put64(item, 0, id);
                put64(item, 16, u64::MAX); // size-only never touches it
            }
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node topology size")?;
            let lengths = user.load(256, 72);
            if u32_at(&lengths, 8) as i32 != expected.map_or(-19, |v| v.len() as i32)
                || u32_at(&lengths, 32) as i32 != geometry.map_or(-19, |v| v.len() as i32)
                || u32_at(&lengths, 56) != 16
            {
                return Err("topology size/absence or engine admission");
            }
            for (index, bytes) in [expected, geometry].into_iter().enumerate() {
                let Some(bytes) = bytes else { continue };
                let address = 1024 + index as u64 * 1024;
                put32(&mut items, index * 24 + 8, bytes.len() as u32 + 8);
                put64(&mut items, index * 24 + 16, address);
                user.store(address, &vec![0xaa; bytes.len() + 8]);
            }
            put32(&mut items, 56, 16);
            put64(&mut items, 64, 4096);
            user.store(256, &items);
            narf_scheduler::block_on_spin(file.ioctl_user(abi::QUERY, 64, &user))
                .map_err(|_| "node topology data")?;
            for (index, bytes) in [expected, geometry].into_iter().enumerate() {
                if let Some(bytes) = bytes {
                    let address = 1024 + index as u64 * 1024;
                    if user.load(address, bytes.len()) != bytes
                        || user.load(address + bytes.len() as u64, 8) != [0xaa; 8]
                    {
                        return Err("topology content or copy extent");
                    }
                }
            }
            if user.load(4096, 16) != [0; 16] {
                return Err("topology advertised execution");
            }
        }
        Ok(())
    }

    fn smoke_intel_topology_query_faults() -> TestResult {
        struct Fuses;
        impl crate::intel_gpu_aux::MmioWindow for Fuses {
            fn read32(&self, offset: u64) -> u32 {
                match offset {
                    0x913c => 5,
                    0x9144 => 6,
                    0x9134 => 5,
                    _ => panic!("topology register"),
                }
            }
            fn write32(&self, _: u64, _: u32) {
                panic!("topology write")
            }
        }
        let mut info = info(Generation::MeteorLake);
        info.topology = Some(Arc::new(
            crate::intel_gpu_topology::GtTopology::read(&Fuses, info.platform).unwrap(),
        ));
        let user = User::new();
        let mut request = [0; 16];
        put32(&mut request, 0, 3);
        put64(&mut request, 8, 256);
        user.store(64, &request);
        for (capacity, flags, fault_read, fault_write, expected) in [
            (0, 0, true, true, 85),
            (84, 0, false, false, -22),
            (85, 1, false, false, -22),
            (85, 0, true, false, -14),
            (85, 0, false, true, -14),
            (85, 0, false, false, 85),
        ] {
            let mut items = [0; 72];
            put64(&mut items, 0, 1);
            put32(&mut items, 8, capacity);
            put32(&mut items, 12, flags);
            put64(&mut items, 16, 1024);
            put64(&mut items, 24, 6);
            put32(&mut items, 32, 85);
            put64(&mut items, 40, 2048);
            put64(&mut items, 48, 2);
            user.store(1024, &[0xaa; 93]);
            user.store(256, &items);
            *user.fail_read.lock() = fault_read.then_some(1024);
            *user.fail_write.lock() = fault_write.then_some(1024);
            query(&info, 64, &user).unwrap();
            *user.fail_read.lock() = None;
            *user.fail_write.lock() = None;
            let mut expected_items = items;
            put32(&mut expected_items, 8, expected as u32);
            put32(&mut expected_items, 32, 85);
            put32(&mut expected_items, 56, 16);
            assert_eq!(user.load(256, 72), expected_items);
            assert_eq!(user.load(1109, 8), [0xaa; 8]);
            if expected < 0 || capacity == 0 {
                assert_eq!(user.load(1024, 85), [0xaa; 85]);
            }
        }
        assert!(!info.submission_ready());
        info.platform = GtPlatform::Battlemage;
        query(&info, 64, &user).unwrap();
        assert_eq!(u32_at(&user.load(256, 72), 8) as i32, -19);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_topology_query_faults
    );

    fn smoke_intel_registry_routes_primary_and_render_nodes() -> TestResult {
        use narf_filesystem::DirOps;
        check(|| {
            for device_id in [0x9a49, 0x7d55, 0x56a0, 0xe20b] {
                let card = Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
                    alloc::string::String::from("Intel routing fixture"),
                    0x8086,
                    device_id,
                    0,
                    0,
                ));
                let index = crate::drm_registry::register_drm_card(card);
                if crate::drm_registry::driver_name(index) != Some("intel-gpu") {
                    return Err("Intel driver identity missing from registry dispatch");
                }
                let info = DeviceInfo::for_card(index).ok_or("registered Intel profile")?;
                if info.device_id != device_id
                    || Some(info.platform) != GtPlatform::from_pci(0x8086, device_id)
                    || info.submission_ready()
                {
                    return Err("registered card facts or unproven submission");
                }
                check_card_hwconfig(index, None)?;
                for name in [
                    alloc::format!("card{index}"),
                    alloc::format!("renderD{}", index + 128),
                ] {
                    let file = crate::drm_devfs_bridge::DriDir
                        .lookup(&name)
                        .ok_or("DRM node")?;
                    let other = crate::drm_devfs_bridge::DriDir
                        .lookup(&name)
                        .ok_or("second open")?;
                    let user = User::new();
                    let mut request = [0; 16];
                    put32(&mut request, 0, 4); // actual PCI device ID
                    put64(&mut request, 8, 256);
                    user.store(64, &request);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GETPARAM, 64, &user))
                        .map_err(|_| "GETPARAM through node")?;
                    if u32_at(&user.load(256, 4), 0) != u32::from(device_id) {
                        return Err("GETPARAM from another card");
                    }
                    put64(&mut request, 0, 4096);
                    put64(&mut request, 8, 0);
                    user.store(64, &request);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_CREATE, 64, &user))
                        .map_err(|_| "GEM_CREATE through node")?;
                    let handle = u32_at(&user.load(64, 16), 8);
                    let mut mmap = [0; 32];
                    put32(&mut mmap, 0, handle);
                    put64(&mut mmap, 16, 2); // I915_MMAP_OFFSET_WB
                    user.store(64, &mmap);
                    if narf_scheduler::block_on_spin(other.ioctl_user(
                        abi::GEM_MMAP_OFFSET,
                        64,
                        &user,
                    )) != Err(FsError::NotFound)
                    {
                        return Err("node opens shared GEM handles");
                    }
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_MMAP_OFFSET, 64, &user))
                        .map_err(|_| "MMAP_OFFSET through node")?;
                    let offset = u64_at(&user.load(64, 32), 8);
                    let backing = file.mmap_backing(offset, 4096).map_err(|_| "node mmap")?;
                    if backing.frames.len() != 1 || backing.lifetime.is_none() {
                        return Err("node mmap did not retain GEM backing");
                    }
                    let mut close = [0; 8];
                    put32(&mut close, 0, handle);
                    user.store(64, &close);
                    narf_scheduler::block_on_spin(file.ioctl_user(abi::GEM_CLOSE, 64, &user))
                        .map_err(|_| "GEM_CLOSE through node")?;
                    if file.mmap_backing(offset, 4096).is_ok() {
                        return Err("closed handle still maps through node");
                    }
                }
            }
            for (vendor, device) in [(0x8086, 0xffff), (0x1002, 0x7d55)] {
                let index = crate::drm_registry::register_drm_card(Arc::new(
                    crate::drm_devfs_bridge::IntelGpuCard::new(
                        alloc::string::String::new(),
                        vendor,
                        device,
                        0,
                        0,
                    ),
                ));
                if DeviceInfo::for_card(index).is_some()
                    || RenderFile::new().dispatch_card(index, abi::GETPARAM, 0, &User::new())
                        != Some(Err(FsError::NoDevice))
                {
                    return Err("unknown/non-Intel identity admitted");
                }
            }
            let index = crate::drm_registry::register_drm_card(Arc::new(
                crate::drm_devfs_bridge::BochsCard::new(alloc::string::String::new()),
            ));
            if DeviceInfo::for_card(index).is_some()
                || RenderFile::new()
                    .dispatch_card(index, abi::GETPARAM, 0, &User::new())
                    .is_some()
            {
                return Err("another driver's ioctl intercepted");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_registry_routes_primary_and_render_nodes
    );

    fn smoke_intel_gem_namespace_mapping_and_close() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let other = RenderFile::new();
            let user = User::new();
            let mut create = [0; 16];
            put64(&mut create, 0, 4097);
            user.store(64, &create);
            invoke(&file, &user, abi::GEM_CREATE).map_err(|_| "create")?;
            let reply = user.load(64, 16);
            let handle = u32_at(&reply, 8);
            if u64_at(&reply, 0) != 8192 {
                return Err("create must round to a page");
            }
            if other.gem.object(handle).is_ok() {
                return Err("foreign handle resolved");
            }
            let object = file.gem.object(handle).map_err(|_| "own handle")?;
            let mut zeroes = [1; 8192];
            object.read(0, &mut zeroes).map_err(|_| "read zeroes")?;
            if zeroes != [0; 8192] {
                return Err("GEM allocation leaked old bytes");
            }
            object
                .write(4094, &[0x12, 0x34, 0x56, 0x78])
                .map_err(|_| "cross-page write")?;
            let mut data = [0; 4];
            object
                .read(4094, &mut data)
                .map_err(|_| "cross-page read")?;
            if data != [0x12, 0x34, 0x56, 0x78] {
                return Err("cross-page data corrupted");
            }
            let offset = file.gem.mmap_offset(handle).map_err(|_| "mmap offset")?;
            if other.gem.mmap_backing(offset, 4096).is_ok()
                || file.gem.mmap_backing(offset, 8193).is_ok()
                || file.gem.mmap_backing(offset + 1, 4096).is_ok()
                || file.gem.mmap_backing(offset + 8192, 4096).is_ok()
            {
                return Err("mmap escaped handle ownership/extent");
            }
            let mapping = file
                .gem
                .mmap_backing(offset + 4096, 4096)
                .map_err(|_| "subrange mmap")?;
            if mapping.frames != object.pages().skip(1).collect::<Vec<_>>() {
                return Err("mmap frame offset");
            }
            let references = Arc::strong_count(&object);
            file.gem.close(handle).map_err(|_| "close")?;
            if file.gem.object(handle).is_ok() || Arc::strong_count(&object) != references - 1 {
                return Err("close did not drop precisely the handle owner");
            }
            if mapping.lifetime.is_none() {
                return Err("mmap failed to retain backing");
            }
            object
                .read(4094, &mut data)
                .map_err(|_| "mapping lifetime after close")?;
            if data != [0x12, 0x34, 0x56, 0x78] {
                return Err("close released retained data");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_gem_namespace_mapping_and_close
    );

    fn smoke_intel_create_copy_failure_and_limits() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put64(&mut request, 0, 4096);
            user.store(64, &request);
            *user.fail_write.lock() = Some(64);
            if invoke(&file, &user, abi::GEM_CREATE) != Err(FsError::BadAddress) {
                return Err("copy failure lost EFAULT");
            }
            *user.fail_write.lock() = None;
            invoke(&file, &user, abi::GEM_CREATE).map_err(|_| "create after failed copy")?;
            if u32_at(&user.load(64, 16), 8) != 0x4000_0000 {
                return Err("failed copy consumed a GEM handle");
            }
            for size in [0, u64::MAX, 256 * 1024 * 1024 + 1] {
                put64(&mut request, 0, size);
                user.store(64, &request);
                if invoke(&file, &user, abi::GEM_CREATE) != Err(FsError::InvalidData) {
                    return Err("invalid allocation extent");
                }
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_create_copy_failure_and_limits
    );

    fn smoke_intel_query_two_pass_and_item_errors() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 3);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            let mut items = [0; 72];
            put64(&mut items, 0, 4); // memory regions
            put64(&mut items, 24, 2); // engines
            put64(&mut items, 48, u64::MAX);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "size query")?;
            let sizes = user.load(256, 72);
            if u32_at(&sizes, 8) != 104
                || u32_at(&sizes, 32) != 16
                || u32_at(&sizes, 56) as i32 != -22
            {
                return Err("two-pass query sizes/per-item failure");
            }
            put32(&mut items, 8, 104);
            put64(&mut items, 16, 1024);
            put32(&mut items, 32, 15); // undersized engine output
            put64(&mut items, 40, 2048);
            user.store(2048, &[0xaa; 16]);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "data query")?;
            let memory = user.load(1024, 104);
            if u32_at(&memory, 0) != 1
                || u32_at(&memory, 16) != 0
                || u64_at(&memory, 24) != 0x8000_0000
                || u64_at(&memory, 32) != 0x8000_0000
                || memory[40..].iter().any(|v| *v != 0)
            {
                return Err("memory query wire fields/reserved bytes");
            }
            if u32_at(&user.load(256, 72), 32) as i32 != -22 || user.load(2048, 16) != [0xaa; 16] {
                return Err("short query overwrote output");
            }
            put32(&mut items, 8, 104);
            put64(&mut items, 16, u64::MAX - 8);
            user.store(256, &items);
            invoke(&file, &user, abi::QUERY).map_err(|_| "per-item EFAULT query")?;
            if u32_at(&user.load(256, 72), 8) as i32 != -14 {
                return Err("query data fault not item EFAULT");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_query_two_pass_and_item_errors
    );

    fn smoke_intel_hwconfig_query_faults_and_copy_extent() -> TestResult {
        // Local Linux i915_query.c::query_hwconfig_blob: size-only does not
        // dereference data_ptr; short buffers are EINVAL and copies are exact.
        check(|| {
            let bytes: Vec<u8> = [0x9000u32, 2, 0xffffffff, 0x01020304, 7, 1, 8]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let mut info = info(Generation::MeteorLake);
            info.hwconfig = Some(Arc::new(HardwareConfig::parse(bytes.clone()).unwrap()));
            let user = User::new();
            let file = RenderFile::new();
            let mut request = [0; 16];
            put32(&mut request, 0, 2);
            put64(&mut request, 8, 256);
            user.store(64, &request);
            for (capacity, flags, pointer, expected) in [
                (0, 0, u64::MAX, 28),
                (27, 0, 1024, -22),
                (-1, 0, 1024, -22),
                (28, 1, 1024, -22),
                (28, 0, 0, -14),
                (28, 0, u64::MAX - 8, -14),
                (28, 0, 1024, 28),
                (36, 0, 1024, 28),
            ] {
                let mut items = [0; 48];
                put64(&mut items, 0, 5);
                put32(&mut items, 8, capacity as u32);
                put32(&mut items, 12, flags);
                put64(&mut items, 16, pointer);
                put64(&mut items, 24, 2); // a later valid item still runs
                user.store(256, &items);
                user.store(1024, &[0xaa; 36]);
                file.dispatch(&info, abi::QUERY, 64, &user)
                    .unwrap()
                    .map_err(|_| "HWCONFIG item query")?;
                let result = user.load(256, 48);
                if u32_at(&result, 8) as i32 != expected
                    || result[..8] != items[..8]
                    || result[12..32] != items[12..32]
                    || u32_at(&result, 32) != 16
                {
                    return Err("HWCONFIG per-item length/isolation or input fields changed");
                }
                let output = user.load(1024, 36);
                if capacity >= 28 && flags == 0 && pointer == 1024 {
                    if output[..28] != bytes || output[28..] != [0xaa; 8] {
                        return Err("HWCONFIG output extent/order");
                    }
                } else if output != [0xaa; 36] {
                    return Err("failed/size-only item wrote output");
                }
            }
            *user.fail_write.lock() = Some(264); // item length itself faults
            if file.dispatch(&info, abi::QUERY, 64, &user) != Some(Err(FsError::BadAddress)) {
                return Err("length copy fault did not fail ioctl");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_hwconfig_query_faults_and_copy_extent
    );

    fn smoke_intel_context_vm_lifetime_and_foreign_ids() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let other = RenderFile::new();
            let user = User::new();
            user.store(64, &[0; 16]);
            invoke(&file, &user, abi::GEM_VM_CREATE).map_err(|_| "VM create")?;
            let vm = u32_at(&user.load(64, 16), 12);
            user.store(64, &[0; 8]);
            invoke(&file, &user, abi::GEM_CONTEXT_CREATE).map_err(|_| "context create")?;
            let ctx = u32_at(&user.load(64, 8), 0);
            let mut parameter = [0; 24];
            put32(&mut parameter, 0, ctx);
            put64(&mut parameter, 8, 9);
            put64(&mut parameter, 16, vm as u64);
            user.store(64, &parameter);
            invoke(&file, &user, abi::GEM_CONTEXT_SETPARAM).map_err(|_| "bind explicit VM")?;
            if invoke(&other, &user, abi::GEM_CONTEXT_SETPARAM) != Err(FsError::NotFound) {
                return Err("foreign context resolved");
            }
            let old_vm = file
                .namespaces
                .lock()
                .contexts
                .get(&ctx)
                .expect("ctx")
                .vm
                .clone();
            let mut destroy = [0; 16];
            put32(&mut destroy, 12, vm);
            user.store(64, &destroy);
            invoke(&file, &user, abi::GEM_VM_DESTROY).map_err(|_| "VM destroy")?;
            user.store(64, &parameter);
            invoke(&file, &user, abi::GEM_CONTEXT_GETPARAM).map_err(|_| "get retained VM")?;
            let new_vm = u64_at(&user.load(64, 24), 16) as u32;
            if new_vm == vm
                || !Arc::ptr_eq(
                    file.namespaces
                        .lock()
                        .vms
                        .get(&new_vm)
                        .expect("new VM handle"),
                    &old_vm,
                )
            {
                return Err("destroyed VM handle invalidated the context VM owner");
            }
            put32(&mut parameter, 0, 0);
            user.store(64, &parameter);
            if invoke(&other, &user, abi::GEM_CONTEXT_SETPARAM) != Err(FsError::NotFound) {
                return Err("foreign VM resolved");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_context_vm_lifetime_and_foreign_ids
    );

    fn smoke_intel_extension_validation_is_transactional() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let mut request = [0; 16];
            put32(&mut request, 4, 1);
            put64(&mut request, 8, 256);
            let mut extension = [0; 56];
            put64(&mut extension, 0, 256); // cycle
            put64(&mut extension, 40, 4); // NO_ERROR_CAPTURE parameter
            put64(&mut extension, 48, 1);
            user.store(64, &request);
            user.store(256, &extension);
            if invoke(&file, &user, abi::GEM_CONTEXT_CREATE_EXT) != Err(FsError::InvalidData) {
                return Err("cyclic context extension");
            }
            if file.namespaces.lock().next_context != 1 {
                return Err("invalid extension allocated context");
            }
            put64(&mut extension, 0, 0);
            user.store(256, &extension);
            invoke(&file, &user, abi::GEM_CONTEXT_CREATE_EXT)
                .map_err(|_| "valid context extension")?;
            if !file
                .namespaces
                .lock()
                .contexts
                .get(&1)
                .expect("context")
                .no_error_capture
            {
                return Err("context creation extension ignored");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_extension_validation_is_transactional
    );

    fn smoke_intel_generation_admission_is_independent_of_display() -> TestResult {
        check(|| {
            for entry in crate::intel_gpu::DEVICE_TABLE {
                let expected = match entry.generation {
                    Generation::TigerLake | Generation::AlderLake => {
                        SubmissionProfile::Gen12Execlists
                    }
                    Generation::MeteorLake => SubmissionProfile::XeLpgGuC,
                    Generation::PantherLake => SubmissionProfile::Unsupported,
                };
                if SubmissionProfile::for_generation(entry.generation) != expected {
                    return Err("submission generation dispatch");
                }
                if info(entry.generation).submission_ready() {
                    return Err("display support admitted an uninitialized GT");
                }
            }
            let file = RenderFile::new();
            let user = User::new();
            for param in [9, 18, 35, 37, 44, 50, 55] {
                let mut request = [0; 16];
                put32(&mut request, 0, param);
                put64(&mut request, 8, 256);
                user.store(64, &request);
                invoke(&file, &user, abi::GETPARAM).map_err(|_| "feature query")?;
                if user.load(256, 4) != [0; 4] {
                    return Err("unsupported render capability advertised");
                }
            }
            if invoke(&file, &user, abi::GEM_EXECBUFFER2).is_ok() {
                return Err("uninitialized submission reported success");
            }
            if invoke(&file, &user, abi::GEM_CREATE ^ (1 << 16)) != Err(FsError::InvalidData) {
                return Err("ioctl with wrong size accepted");
            }
            if file
                .dispatch(
                    &info(Generation::MeteorLake),
                    crate::drm_uapi::DRM_IOCTL_VERSION,
                    64,
                    &user,
                )
                .is_some()
            {
                return Err("generic DRM ioctl stolen by Intel");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_generation_admission_is_independent_of_display
    );

    fn smoke_intel_exec_residency_retains_gem_and_maps_xelpg() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let a = file
                .gem
                .create(8192, |_, _| Ok(()))
                .map_err(|_| "allocate data")?;
            let b = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate batch")?;
            let data = file.gem.object(a).map_err(|_| "data handle")?;
            let batch = file.gem.object(b).map_err(|_| "batch handle")?;
            let data_phys: Vec<_> = data.pages().collect();
            let batch_phys = batch.pages().next().ok_or("batch page")?;
            let mut request = [0; 64];
            put64(&mut request, 0, 256);
            put32(&mut request, 8, 2);
            put32(&mut request, 12, 8);
            put32(&mut request, 16, 8);
            put64(&mut request, 40, 0x1801); // render | NO_RELOC | HANDLE_LUT
            let mut objects = [0; 112];
            put32(&mut objects, 0, a);
            put64(&mut objects, 24, 0x20_0000);
            put64(&mut objects, 32, 0x1c); // WRITE | SUPPORTS_48B | PINNED
            put32(&mut objects, 56, b);
            put64(&mut objects, 80, 0x40_0000);
            put64(&mut objects, 88, 0x18); // SUPPORTS_48B | PINNED
            user.store(64, &request);
            user.store(256, &objects);
            let exec = crate::intel_gpu_exec::ExecRequest::read(&user, 64, &file.gem)
                .map_err(|_| "valid execbuffer")?;
            if exec.batch_va != 0x40_0008 || exec.batch_len != 8 || exec.context_id != 0 {
                return Err("batch selection/extent");
            }
            let gen12 = exec
                .address_space(crate::intel_gpu_gtt::PteFormat::Gen12, 3)
                .map_err(|_| "Gen12 residency")?;
            let xelpg = exec
                .address_space(crate::intel_gpu_gtt::PteFormat::XeLpg, 15)
                .map_err(|_| "Xe-LPG residency")?;
            if gen12.root_phys() == xelpg.root_phys() {
                return Err("VMs share a root table");
            }
            file.gem.close(a).map_err(|_| "data close")?;
            file.gem.close(b).map_err(|_| "batch close")?;
            drop(exec);
            drop(file);
            for space in [&gen12, &xelpg] {
                for (va, physical) in [
                    (0x20_0123, data_phys[0] + 0x123),
                    (0x20_1000, data_phys[1]),
                    (0x40_0008, batch_phys + 8),
                ] {
                    if space.translate(va)
                        != Ok(crate::intel_gpu_ppgtt::WalkOutcome::Mapped(physical))
                    {
                        return Err("owned residency translation after fd close");
                    }
                }
                if !matches!(
                    space.translate(0x30_0000),
                    Ok(crate::intel_gpu_ppgtt::WalkOutcome::NotMapped { .. })
                ) {
                    return Err("unbound address resolved");
                }
            }
            // Both page tables retain the leaf objects independently of the fd.
            if Arc::strong_count(&data) != 3 || Arc::strong_count(&batch) != 3 {
                return Err("residency failed to retain buffer ownership");
            }
            drop(gen12);
            drop(xelpg);
            if Arc::strong_count(&data) != 1 || Arc::strong_count(&batch) != 1 {
                return Err("residency teardown leaked leaf owners");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_exec_residency_retains_gem_and_maps_xelpg
    );

    fn smoke_intel_exec_rejects_hostile_wire_before_vm_changes() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let a = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let b = file
                .gem
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let mut request = [0; 64];
            put64(&mut request, 0, 256);
            put32(&mut request, 8, 2);
            put32(&mut request, 16, 8);
            put64(&mut request, 40, 0x801);
            let mut objects = [0; 112];
            put32(&mut objects, 0, a);
            put64(&mut objects, 24, 0x20_0000);
            put64(&mut objects, 32, 0x18);
            put32(&mut objects, 56, b);
            put64(&mut objects, 80, 0x40_0000);
            put64(&mut objects, 88, 0x18);
            let parse = |request: &[u8], objects: &[u8]| {
                user.store(64, request);
                user.store(256, objects);
                crate::intel_gpu_exec::ExecRequest::read(&user, 64, &file.gem)
            };
            if parse(&request, &objects).is_err() {
                return Err("baseline execbuffer rejected");
            }
            let mut invalid = request;
            put64(&mut invalid, 40, 0xa01); // privileged SECURE bit
            if parse(&invalid, &objects).is_ok() {
                return Err("secure execution admitted");
            }
            put64(&mut invalid, 40, 0x801);
            put32(&mut invalid, 12, 4096);
            if parse(&invalid, &objects).is_ok() {
                return Err("batch past BO extent");
            }
            invalid = request;
            put32(&mut invalid, 8, 4097);
            if parse(&invalid, &objects).is_ok() {
                return Err("unbounded object list");
            }
            for (field, value) in [
                (80, 0x20_0000),
                (80, 0x0001_0000_0040_0000),
                (80, u64::MAX - 4095),
                (88, 0x10),
                (64, 1),
            ] {
                let mut bad_objects = objects;
                put64(&mut bad_objects, field, value);
                // 0x10 alone is a valid 32-bit pinned object at 4MiB; test
                // that flag separately at an address requiring SUPPORTS_48B.
                if field == 88 {
                    put64(&mut bad_objects, 80, 0x1_0000_0000);
                }
                if parse(&request, &bad_objects).is_ok() {
                    return Err("invalid residency placement/flags accepted");
                }
            }
            let mut duplicate = objects;
            put32(&mut duplicate, 56, a);
            if parse(&request, &duplicate).is_ok() {
                return Err("duplicate GEM object accepted");
            }
            user.store(64, &request);
            user.store(256, &objects);
            if invoke(&file, &user, abi::GEM_EXECBUFFER2) != Err(FsError::NotImplemented) {
                return Err("valid plan bypassed missing GT admission");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_exec_rejects_hostile_wire_before_vm_changes
    );

    fn smoke_intel_pread_pwrite_and_mmap_wire() -> TestResult {
        check(|| {
            let file = RenderFile::new();
            let user = User::new();
            let handle = file
                .gem
                .create(24576, |_, _| Ok(()))
                .map_err(|_| "allocate")?;
            let pattern: Vec<_> = (0..20000).map(|i| (i % 251) as u8).collect();
            user.store(1024, &pattern);
            let mut request = [0; 32];
            put32(&mut request, 0, handle);
            put64(&mut request, 8, 4090);
            put64(&mut request, 16, 20000);
            put64(&mut request, 24, 1024);
            user.store(64, &request);
            invoke(&file, &user, abi::GEM_PWRITE).map_err(|_| "chunked pwrite")?;
            user.store(1024, &vec![0; 20000]);
            invoke(&file, &user, abi::GEM_PREAD).map_err(|_| "chunked pread")?;
            if user.load(1024, 20000) != pattern {
                return Err("ioctl copy corrupted cross-page/chunk data");
            }
            put64(&mut request, 8, u64::MAX - 15);
            user.store(64, &request);
            if invoke(&file, &user, abi::GEM_PREAD) != Err(FsError::InvalidData) {
                return Err("pread wrapped its object extent");
            }
            request = [0; 32];
            put32(&mut request, 0, handle);
            put64(&mut request, 16, 2); // WB
            user.store(64, &request);
            invoke(&file, &user, abi::GEM_MMAP_OFFSET).map_err(|_| "WB mmap offset")?;
            let reply = user.load(64, 32);
            if u64_at(&reply, 8) != file.gem.mmap_offset(handle).map_err(|_| "offset")? {
                return Err("mmap wire offset");
            }
            put64(&mut request, 16, 1); // WC cannot be implemented by a WB RAM alias.
            user.store(64, &request);
            if invoke(&file, &user, abi::GEM_MMAP_OFFSET) != Err(FsError::InvalidData) {
                return Err("incompatible cache alias admitted");
            }
            let mut caching = [0; 8];
            put32(&mut caching, 0, handle);
            put32(&mut caching, 4, 1);
            user.store(64, &caching);
            *user.fail_write.lock() = Some(64);
            if invoke(&file, &user, abi::GEM_SET_CACHING) != Ok(0)
                || invoke(&file, &user, abi::GEM_GET_CACHING) != Err(FsError::BadAddress)
            {
                return Err("SET_CACHING requires only a readable request");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_pread_pwrite_and_mmap_wire
    );

    fn smoke_intel_prime_import_identity_offsets_and_mapping_owner() -> TestResult {
        check(|| {
            let exporter = GemState::new();
            let importer = GemState::new();
            let handle = exporter
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "export allocation")?;
            let unrelated = importer
                .create(4096, |_, _| Ok(()))
                .map_err(|_| "importer allocation")?;
            let object = exporter.object(handle).map_err(|_| "export object")?;
            object
                .write(17, &[0x45, 0x67])
                .map_err(|_| "write shared bytes")?;
            let prime = crate::drm_devfs_bridge::intel_dma_buf_file(3, object.clone());
            let imported = crate::drm_devfs_bridge::intel_prime_import(3, &importer, &prime)
                .map_err(|_| "PRIME import")?;
            if imported == unrelated
                || !Arc::ptr_eq(
                    &object,
                    &importer.object(imported).map_err(|_| "imported handle")?,
                )
            {
                return Err("PRIME import replaced another handle or copied identity");
            }
            if crate::drm_devfs_bridge::intel_prime_import(3, &importer, &prime) != Ok(imported)
                || crate::drm_devfs_bridge::intel_prime_import(4, &importer, &prime)
                    != Err(FsError::InvalidData)
            {
                return Err("PRIME reimport identity or cross-card admission");
            }
            let exported_offset = exporter.mmap_offset(handle).map_err(|_| "export offset")?;
            let imported_offset = importer
                .mmap_offset(imported)
                .map_err(|_| "import offset")?;
            let unrelated_offset = importer
                .mmap_offset(unrelated)
                .map_err(|_| "other offset")?;
            if imported_offset != exported_offset || imported_offset == unrelated_offset {
                return Err("import mmap offset collision");
            }
            let mapping = prime.mmap_backing(0, 4096).map_err(|_| "PRIME mmap")?;
            if prime.mmap_backing(4096, 4096).is_ok()
                || mapping.frames != object.pages().collect::<Vec<_>>()
            {
                return Err("PRIME mmap frames or extent");
            }
            exporter.close(handle).map_err(|_| "export GEM_CLOSE")?;
            importer.close(imported).map_err(|_| "import GEM_CLOSE")?;
            drop(exporter);
            drop(importer);
            drop(prime);
            if mapping.lifetime.is_none() || Arc::strong_count(&object) != 2 {
                return Err("PRIME mapping lost backing after all fds closed");
            }
            let mut bytes = [0; 2];
            object.read(17, &mut bytes).map_err(|_| "retained data")?;
            if bytes != [0x45, 0x67] {
                return Err("PRIME storage changed after close");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_render",
        smoke_intel_prime_import_identity_offsets_and_mapping_owner
    );
}
