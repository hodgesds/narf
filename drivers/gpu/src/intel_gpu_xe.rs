//! Native Xe per-open VM/queue ABI over the owned GuC RCS backend.
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_vm.c,
//! xe_exec_queue.c, xe_exec.c, xe_sync.c and xe_wait_user_fence.c.
use crate::{
    drm::syncobj::{self as so, SyncObjTable},
    intel_gpu_exec::ResidentBatch,
    intel_gpu_gem::GemState,
    intel_gpu_render::DeviceInfo,
    intel_gpu_uapi::{put32, put64, u32_at, u64_at},
    intel_gpu_user::{UserBatch, UserContext},
    intel_gpu_xe_sync::Sync,
    intel_gpu_xe_uapi as abi,
    intel_gpu_xe_vm::{read, zero, Bind, Vm},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use core::sync::atomic::{AtomicBool, Ordering};
use narf_filesystem::{FsError, IoctlContext};
use narf_lib::sync::IrqSafeSpinLock;

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
                zero(&wire[..8])?;
                zero(&wire[34..56])?;
                let size = u64_at(&wire, 8);
                let flags = u32_at(&wire, 20);
                let supported_flags =
                    if info.platform == crate::intel_gpu_gt::GtPlatform::Battlemage {
                        8
                    } else {
                        0
                    };
                if size == 0
                    || size % 4096 != 0
                    || u32_at(&wire, 16) != 1
                    || flags & !supported_flags != 0
                {
                    return Err(FsError::InvalidData);
                }
                let caching = u16::from_le_bytes(wire[32..34].try_into().unwrap());
                // Linux overrides system-memory CPU mappings to WB on dGPU.
                if caching != 1 && !(caching == 2 && info.platform.is_discrete()) {
                    return Err(FsError::NotImplemented);
                }
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
                gem.create_for_vm(size, vm.as_ref().map(|vm| vm.identity), |handle, _| {
                    put32(&mut wire, 28, handle);
                    user.write(address, &wire)
                })
                .map(|_| ())
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
        zero(&wire[16..20])?;
        zero(&wire[32..48])?;
        if u32_at(&wire, 8) != 0x0001_0001 {
            return Err(FsError::InvalidData);
        }
        let instance = read(user, u64_at(&wire, 24), 8)?;
        zero(&instance[2..8])?;
        let class = u16::from_le_bytes(instance[..2].try_into().unwrap());
        if !matches!(class, 0 | 5) {
            return Err(FsError::InvalidData);
        }
        let mut extensions = u64_at(&wire, 0);
        let mut seen = BTreeSet::new();
        let (mut priority, mut timeslice) = (2, 1000);
        while extensions != 0 {
            if seen.len() == 16 || !seen.insert(extensions) {
                return Err(FsError::InvalidData);
            }
            let ext = read(user, extensions, 48)?;
            zero(&ext[8..16])?;
            zero(&ext[20..24])?;
            zero(&ext[32..48])?;
            let value = u64_at(&ext, 24);
            match u32_at(&ext, 16) {
                0 if value <= 1 => priority = if value == 0 { 3 } else { 2 },
                0 if value == 2 => return Err(FsError::OperationNotPermitted),
                0 => return Err(FsError::InvalidData),
                1 if (1..=100_000).contains(&value) => timeslice = value as u32,
                1 => return Err(FsError::InvalidData),
                _ => return Err(FsError::NotImplemented),
            }
            extensions = u64_at(&ext, 0);
        }
        let context = UserContext::new();
        context.configure_schedule(priority, timeslice)?;
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
        syncobjs: &IrqSafeSpinLock<SyncObjTable>,
    ) -> Option<Result<u64, FsError>> {
        match cmd {
            abi::VM_BIND => Some(
                self.bind(info, address, user, gem, syncobjs)
                    .await
                    .map(|_| 0),
            ),
            abi::EXEC => Some(self.exec(info, address, user, syncobjs).await.map(|_| 0)),
            abi::WAIT_USER_FENCE => Some(self.wait_user(address, user).await.map(|_| 0)),
            _ => self.dispatch(info, cmd, address, user, gem),
        }
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
        state.mappings = mappings;
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
        if count > 1 {
            return Err(FsError::InvalidData);
        }
        let queue = self.queue(u32_at(&wire, 8))?;
        if queue.bind {
            return Err(FsError::InvalidData);
        }
        let sync = Sync::read(user, u64_at(&wire, 16), u32_at(&wire, 12), table)?;
        let backend = info.backend.as_ref().ok_or(FsError::NoDevice)?;
        let _order = queue.context.serial.lock().await;
        sync.wait().await;
        if let Some(previous) = queue.context.last() {
            previous
                .wait()
                .await
                .map_err(|_| crate::intel_gpu_user::io_error())?;
        }
        let mut state = queue.vm.state.lock().await;
        loop {
            queue.check()?;
            let status = backend
                .status()
                .filter(|s| s.platform == info.platform)
                .ok_or(FsError::NoDevice)?;
            queue.context.check_epoch(status.epoch)?;
            let resident = ResidentBatch::from_vm(
                status.platform,
                &state.mappings,
                (count == 1).then_some(u64_at(&wire, 24)),
                queue.vm.scratch,
                sync.user_fence,
            )?;
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
        let start = narf_time::monotonic_ns();
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
            if deadline.is_some_and(|end| narf_time::monotonic_ns() >= end) {
                break Err(FsError::TimedOut);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        };
        if flags == 0 && timeout >= 0 {
            let remaining =
                (timeout as u64).saturating_sub(narf_time::monotonic_ns().saturating_sub(start));
            user.write(
                address.checked_add(40).ok_or(FsError::BadAddress)?,
                &remaining.to_le_bytes(),
            )?;
        }
        result
    }
}
