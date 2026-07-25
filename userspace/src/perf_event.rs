use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, copy_to_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;
use narf_linux_perf_uapi::{
    PerfEventAttr, PERF_ATTR_FLAG_DISABLED, PERF_ATTR_FLAG_ENABLE_ON_EXEC, PERF_ATTR_SIZE_VER0,
    PERF_COUNT_HW_BRANCH_INSTRUCTIONS, PERF_COUNT_HW_BRANCH_MISSES, PERF_COUNT_HW_CACHE_LL,
    PERF_COUNT_HW_CACHE_MISSES, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS,
    PERF_COUNT_HW_CPU_CYCLES, PERF_COUNT_HW_INSTRUCTIONS, PERF_COUNT_SW_DUMMY, PERF_FORMAT_GROUP,
    PERF_FORMAT_ID, PERF_FORMAT_LOST, PERF_FORMAT_TOTAL_TIME_ENABLED,
    PERF_FORMAT_TOTAL_TIME_RUNNING, PERF_RECORD_LOST, PERF_RECORD_SAMPLE, PERF_SAMPLE_CPU,
    PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD,
    PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID, PERF_SAMPLE_TIME, PERF_TYPE_HARDWARE,
    PERF_TYPE_HW_CACHE, PERF_TYPE_RAW, PERF_TYPE_SOFTWARE,
};

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);
static PERF_EVENT_REGISTRY: IrqSafeSpinLock<Vec<Weak<PerfEventFile>>> =
    IrqSafeSpinLock::new(Vec::new());
#[cfg(target_arch = "x86_64")]
static PMI_VECTOR: IrqSafeSpinLock<Option<u8>> = IrqSafeSpinLock::new(None);
const SAMPLE_CPU_SLOTS: usize = narf_lib::percpu::MAX_CPUS;
static PENDING_SAMPLES: [PendingSample; SAMPLE_CPU_SLOTS] =
    [const { PendingSample::new() }; SAMPLE_CPU_SLOTS];
static PENDING_SAMPLE_LOST: AtomicU64 = AtomicU64::new(0);

struct PendingSample {
    state: AtomicU8,
    task: AtomicU64,
    ip: AtomicU64,
    time: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    counters: AtomicU8,
}

impl PendingSample {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(0),
            task: AtomicU64::new(0),
            ip: AtomicU64::new(0),
            time: AtomicU64::new(0),
            #[cfg(target_arch = "x86_64")]
            counters: AtomicU8::new(0),
        }
    }
}

const PERF_FORMAT_SUPPORTED: u64 = (1 << 5) - 1;

const PERF_ATTR_IMPLEMENTED: u64 = PERF_ATTR_FLAG_DISABLED | PERF_ATTR_FLAG_ENABLE_ON_EXEC;

const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
const PERF_EVENT_IOC_RESET: u32 = 0x2403;
const PERF_EVENT_IOC_ID: u32 = 0x8008_2407;
const PERF_IOC_FLAG_GROUP: usize = 1;
const PERF_MMAP_PAGE_BYTES: usize = 4096;
const PERF_MMAP_MAX_DATA_PAGES: usize = 256;
const PERF_MMAP_LOCK_OFFSET: usize = 8;
const PERF_MMAP_OFFSET_OFFSET: usize = 16;
const PERF_MMAP_TIME_ENABLED_OFFSET: usize = 24;
const PERF_MMAP_TIME_RUNNING_OFFSET: usize = 32;
const PERF_MMAP_DATA_HEAD_OFFSET: usize = 1024;
const PERF_MMAP_DATA_TAIL_OFFSET: usize = 1032;
const PERF_MMAP_DATA_OFFSET_OFFSET: usize = 1040;
const PERF_MMAP_DATA_SIZE_OFFSET: usize = 1048;
const PERF_SAMPLE_SUPPORTED: u64 = PERF_SAMPLE_IP
    | PERF_SAMPLE_TID
    | PERF_SAMPLE_TIME
    | PERF_SAMPLE_ID
    | PERF_SAMPLE_CPU
    | PERF_SAMPLE_PERIOD
    | PERF_SAMPLE_STREAM_ID
    | PERF_SAMPLE_IDENTIFIER;

struct PerfEventFile {
    attr: PerfEventAttr,
    id: u64,
    target_task: u64,
    target_pid: u64,
    target_cpu: i32,
    enabled: AtomicBool,
    count_base: AtomicU64,
    count_accumulated: AtomicU64,
    enabled_at_ns: AtomicU64,
    time_enabled_ns: AtomicU64,
    registered: AtomicBool,
    sample_lost: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    sample_period: u64,
    mmap_seq: AtomicU32,
    mmap: IrqSafeSpinLock<Option<PerfMmap>>,
    group_members: IrqSafeSpinLock<Vec<Weak<dyn FileOps>>>,
    // A member keeps its leader's open-file description alive. The leader
    // holds only weak member links, so this cannot form a reference cycle.
    _group_leader: Option<Arc<dyn FileOps>>,
    #[cfg(target_arch = "x86_64")]
    pmu_counter: Option<narf_arch::x86_64::pmu::PmuCounter>,
}

struct PerfMmap {
    frames: Vec<narf_memory::PhysFrame>,
    len: usize,
}

impl PerfMmap {
    fn allocate(len: usize) -> Result<Self, FsError> {
        let pages = len / PERF_MMAP_PAGE_BYTES;
        let data_pages = pages.saturating_sub(1);
        if len < PERF_MMAP_PAGE_BYTES * 2
            || len % PERF_MMAP_PAGE_BYTES != 0
            || !data_pages.is_power_of_two()
            || data_pages > PERF_MMAP_MAX_DATA_PAGES
        {
            return Err(FsError::InvalidData);
        }
        let mut frames = Vec::with_capacity(pages);
        while frames.len() < pages {
            let frame = match narf_memory::alloc_frame() {
                Ok(frame) => frame,
                Err(_) => {
                    for frame in frames.drain(..) {
                        narf_memory::free_frame(frame);
                    }
                    return Err(FsError::NoSpace);
                }
            };
            // SAFETY: `frame` is freshly allocated, owned here, and identity
            // mapped for the full 4 KiB page.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().raw() as *mut u8,
                    0,
                    PERF_MMAP_PAGE_BYTES,
                );
            }
            frames.push(frame);
        }
        let mapping = Self { frames, len };
        mapping.write_u64(PERF_MMAP_DATA_OFFSET_OFFSET, PERF_MMAP_PAGE_BYTES as u64);
        mapping.write_u64(
            PERF_MMAP_DATA_SIZE_OFFSET,
            (len - PERF_MMAP_PAGE_BYTES) as u64,
        );
        Ok(mapping)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        // SAFETY: the metadata frame is a live identity-mapped 4 KiB frame and
        // every call site uses a naturally aligned in-page u32 field.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u32,
                value,
            );
        }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        // SAFETY: same as write_u32, for naturally aligned u64 fields.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u64,
                value,
            );
        }
    }

    fn raw_frames(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|frame| frame.start_address().raw())
            .collect()
    }

    fn read_u64_acquire(&self, offset: usize) -> u64 {
        // SAFETY: Linux perf metadata indices are naturally aligned u64
        // locations shared atomically between kernel and userspace.
        let atomic = unsafe {
            &*((self.frames[0].start_address().raw() as usize + offset) as *const AtomicU64)
        };
        atomic.load(Ordering::Acquire)
    }

    fn write_u64_release(&self, offset: usize, value: u64) {
        // SAFETY: same shared-index contract as read_u64_acquire.
        let atomic = unsafe {
            &*((self.frames[0].start_address().raw() as usize + offset) as *const AtomicU64)
        };
        atomic.store(value, Ordering::Release);
    }

    fn write_ring(&self, head: u64, bytes: &[u8]) {
        let data_len = self.len - PERF_MMAP_PAGE_BYTES;
        for (i, byte) in bytes.iter().copied().enumerate() {
            let ring_offset = (head as usize + i) & (data_len - 1);
            let page = 1 + ring_offset / PERF_MMAP_PAGE_BYTES;
            let in_page = ring_offset % PERF_MMAP_PAGE_BYTES;
            // SAFETY: page and in_page are bounded by the allocated data
            // frames; the mapping lock gives this writer exclusive access.
            unsafe {
                core::ptr::write_volatile(
                    (self.frames[page].start_address().raw() as usize + in_page) as *mut u8,
                    byte,
                );
            }
        }
    }
}

impl Drop for PerfMmap {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            narf_memory::free_frame(frame);
        }
    }
}

impl core::fmt::Debug for PerfEventFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfEventFile")
            .field("id", &self.id)
            .field("target_task", &self.target_task)
            .field("target_pid", &self.target_pid)
            .field("target_cpu", &self.target_cpu)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PerfEventFile {
    fn raw_count(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: the counter belongs to this open file and remains allocated
            // until Drop, which cannot run while this method borrows `self`.
            return unsafe { narf_arch::x86_64::pmu::read(&counter) };
        }

        // PERF_COUNT_SW_DUMMY is the only software event admitted until
        // scheduler-owned, per-target software accounting exists. Its specified
        // count is exactly zero.
        0
    }

    fn enable(&self) {
        if !self.enabled.swap(true, Ordering::AcqRel) {
            let raw = self.raw_count();
            let now = narf_time::monotonic_ns();
            self.count_base.store(raw, Ordering::Release);
            self.enabled_at_ns.store(now, Ordering::Release);
            #[cfg(target_arch = "x86_64")]
            if self.sample_period != 0 {
                if let Some(counter) = &self.pmu_counter {
                    // SAFETY: this file owns the live counter.
                    let _ = unsafe {
                        narf_arch::x86_64::pmu::arm_sampling(counter, self.sample_period)
                    };
                }
            }
        }
        self.publish_mmap_state();
    }

    fn disable(&self) {
        if self.enabled.swap(false, Ordering::AcqRel) {
            #[cfg(target_arch = "x86_64")]
            if self.sample_period != 0 {
                if let Some(counter) = &self.pmu_counter {
                    // SAFETY: this file owns the live counter.
                    let _ = unsafe { narf_arch::x86_64::pmu::pause_sampling(counter) };
                }
            }
            let raw = self.raw_count();
            let base = self.count_base.load(Ordering::Acquire);
            self.count_accumulated
                .fetch_add(raw.wrapping_sub(base), Ordering::AcqRel);
            let now = narf_time::monotonic_ns();
            let since = self.enabled_at_ns.load(Ordering::Acquire);
            self.time_enabled_ns
                .fetch_add(now.saturating_sub(since), Ordering::AcqRel);
        }
        self.publish_mmap_state();
    }

    fn reset(&self) {
        self.count_accumulated.store(0, Ordering::Release);
        self.time_enabled_ns.store(0, Ordering::Release);
        if self.enabled.load(Ordering::Acquire) {
            self.count_base.store(self.raw_count(), Ordering::Release);
            self.enabled_at_ns
                .store(narf_time::monotonic_ns(), Ordering::Release);
        }
        self.publish_mmap_state();
    }

    fn snapshot(&self) -> (u64, u64) {
        let mut value = self.count_accumulated.load(Ordering::Acquire);
        let mut time = self.time_enabled_ns.load(Ordering::Acquire);
        if self.enabled.load(Ordering::Acquire) {
            value = value.wrapping_add(
                self.raw_count()
                    .wrapping_sub(self.count_base.load(Ordering::Acquire)),
            );
            time = time.saturating_add(
                narf_time::monotonic_ns()
                    .saturating_sub(self.enabled_at_ns.load(Ordering::Acquire)),
            );
        }
        (value, time)
    }

    fn publish_mmap_state(&self) {
        let (value, time) = self.snapshot();
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return;
        };
        let sequence = self.mmap_seq.fetch_add(2, Ordering::Relaxed);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(1));
        core::sync::atomic::compiler_fence(Ordering::Release);
        // `index == 0` (the zeroed default) tells userspace that direct RDPMC
        // is unavailable; Linux then treats `offset` as the count snapshot.
        mapping.write_u64(PERF_MMAP_OFFSET_OFFSET, value);
        mapping.write_u64(PERF_MMAP_TIME_ENABLED_OFFSET, time);
        mapping.write_u64(PERF_MMAP_TIME_RUNNING_OFFSET, time);
        core::sync::atomic::compiler_fence(Ordering::Release);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(2));
    }

    fn push_record(&self, record: &[u8]) -> bool {
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return false;
        };
        let data_size = (mapping.len - PERF_MMAP_PAGE_BYTES) as u64;
        let head = mapping.read_u64_acquire(PERF_MMAP_DATA_HEAD_OFFSET);
        let tail = mapping.read_u64_acquire(PERF_MMAP_DATA_TAIL_OFFSET);
        if head.wrapping_sub(tail) > data_size
            || record.len() as u64 > data_size.saturating_sub(head.wrapping_sub(tail))
        {
            self.sample_lost.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        mapping.write_ring(head, record);
        mapping.write_u64_release(
            PERF_MMAP_DATA_HEAD_OFFSET,
            head.wrapping_add(record.len() as u64),
        );
        true
    }

    fn sample_record(&self, ip: u64, pid: u32, tid: u32, now: u64) -> bool {
        let sample_type = self.attr.sample_type;
        let mut payload = Vec::with_capacity(80);
        let push_u32 = |payload: &mut Vec<u8>, value: u32| {
            payload.extend_from_slice(&value.to_ne_bytes());
        };
        let push_u64 = |payload: &mut Vec<u8>, value: u64| {
            payload.extend_from_slice(&value.to_ne_bytes());
        };
        if sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_IP != 0 {
            push_u64(&mut payload, ip);
        }
        if sample_type & PERF_SAMPLE_TID != 0 {
            push_u32(&mut payload, pid);
            push_u32(&mut payload, tid);
        }
        if sample_type & PERF_SAMPLE_TIME != 0 {
            push_u64(&mut payload, now);
        }
        if sample_type & PERF_SAMPLE_ID != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_STREAM_ID != 0 {
            push_u64(&mut payload, self.id);
        }
        if sample_type & PERF_SAMPLE_CPU != 0 {
            push_u32(&mut payload, narf_lib::percpu::current_cpu() as u32);
            push_u32(&mut payload, 0);
        }
        if sample_type & PERF_SAMPLE_PERIOD != 0 {
            push_u64(&mut payload, self.attr.sample_period_or_freq);
        }
        let lost = self.sample_lost.swap(0, Ordering::AcqRel);
        if lost != 0 {
            let mut record = Vec::with_capacity(24);
            push_u32(&mut record, PERF_RECORD_LOST);
            record.extend_from_slice(&0u16.to_ne_bytes());
            record.extend_from_slice(&24u16.to_ne_bytes());
            push_u64(&mut record, self.id);
            push_u64(&mut record, lost);
            if !self.push_record(&record) {
                self.sample_lost.fetch_add(lost, Ordering::Relaxed);
            }
        }

        let size = 8usize.saturating_add(payload.len());
        let Ok(size) = u16::try_from(size) else {
            return false;
        };
        let mut record = Vec::with_capacity(size as usize);
        push_u32(&mut record, PERF_RECORD_SAMPLE);
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&size.to_ne_bytes());
        record.extend_from_slice(&payload);
        self.push_record(&record)
    }

    fn member_files(&self) -> Vec<Arc<dyn FileOps>> {
        self.group_members
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    fn add_group_member(&self, member: &Arc<dyn FileOps>) {
        self.group_members.lock().push(Arc::downgrade(member));
    }

    fn for_group(&self, flags: usize, mut op: impl FnMut(&PerfEventFile)) -> Result<(), FsError> {
        if flags & !PERF_IOC_FLAG_GROUP != 0 {
            return Err(FsError::InvalidData);
        }
        op(self);
        if flags & PERF_IOC_FLAG_GROUP != 0 {
            for file in self.member_files() {
                if let Some(event) = file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PerfEventFile>())
                {
                    op(event);
                }
            }
        }
        Ok(())
    }

    fn push_word(buf: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), FsError> {
        let end = cursor.saturating_add(8);
        let dst = buf.get_mut(*cursor..end).ok_or(FsError::InvalidData)?;
        dst.copy_from_slice(&value.to_ne_bytes());
        *cursor = end;
        Ok(())
    }
}

/// Apply Linux `enable_on_exec` at the point a task commits a new image.
///
/// Events are owned by the monitoring process but keyed by the target task,
/// matching the way the upstream perf CLI opens events for its stopped child.
pub(crate) fn on_exec(task: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_task == task
            && event.attr.flags & PERF_ATTR_FLAG_ENABLE_ON_EXEC != 0
            && event._group_leader.is_none()
        {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::enable);
        }
        true
    });
}

/// Stop task-targeted events when the target process becomes group-dead.
pub(crate) fn on_process_exit(pid: u64, _tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_pid == pid && event._group_leader.is_none() {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::disable);
        }
        true
    });
}

#[cfg(target_arch = "x86_64")]
fn pmi_handler(_cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: this handler is installed only on LVT-PC and runs at CPL0.
    let counters = unsafe { narf_arch::x86_64::pmu::handle_sampling_overflow() };
    if counters == 0 {
        return narf_interrupts::IrqStatus::None;
    }
    let cpu = narf_lib::percpu::current_cpu().min(SAMPLE_CPU_SLOTS - 1);
    let pending = &PENDING_SAMPLES[cpu];
    if pending
        .state
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        PENDING_SAMPLE_LOST.fetch_add(1, Ordering::Relaxed);
        return narf_interrupts::IrqStatus::Handled;
    }
    pending
        .task
        .store(crate::handlers::current_task_id(), Ordering::Relaxed);
    pending
        .ip
        .store(narf_interrupts::interrupted_ip(), Ordering::Relaxed);
    pending
        .time
        .store(narf_time::monotonic_ns(), Ordering::Relaxed);
    pending.counters.store(counters, Ordering::Relaxed);
    pending.state.store(2, Ordering::Release);
    // Wake a parked poll/epoll task so its syscall re-enters normal context
    // and drains this allocation-free IRQ snapshot into the mmap ring.
    narf_net::readiness::notify(0);
    narf_interrupts::IrqStatus::Handled
}

#[cfg(target_arch = "x86_64")]
fn ensure_pmi_route() -> Result<(), ()> {
    let mut slot = PMI_VECTOR.lock();
    if slot.is_some() {
        return Ok(());
    }
    let vector = narf_interrupts::vector::alloc().map_err(|_| ())?;
    narf_interrupts::install_handler_named(vector, "perf-pmi", 0, pmi_handler);
    // SAFETY: APIC bring-up precedes userspace and this programs only the
    // current CPU's LVT-PC entry.
    unsafe { narf_arch::x86_64::pmi::program_current_lvt_pc(vector, false) };
    *slot = Some(vector);
    Ok(())
}

/// Drain allocation-free PMI snapshots into userspace mmap rings from normal
/// syscall context. The IRQ handler captures IP/task/time and rearms hardware;
/// record encoding and readiness wakeups happen here where allocation is safe.
pub(crate) fn drain_irq_samples() {
    let mut notify = false;
    let deferred_lost = PENDING_SAMPLE_LOST.swap(0, Ordering::AcqRel);
    for pending in &PENDING_SAMPLES {
        if pending
            .state
            .compare_exchange(2, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            continue;
        }
        let task = pending.task.load(Ordering::Relaxed);
        let ip = pending.ip.load(Ordering::Relaxed);
        let now = pending.time.load(Ordering::Relaxed);
        #[cfg(target_arch = "x86_64")]
        let counters = pending.counters.load(Ordering::Relaxed);
        {
            let registry = PERF_EVENT_REGISTRY.lock();
            for weak in registry.iter() {
                let Some(event) = weak.upgrade() else {
                    continue;
                };
                #[cfg(target_arch = "x86_64")]
                let matches_counter = event
                    .pmu_counter
                    .is_some_and(|counter| counters & (1 << counter.idx) != 0);
                #[cfg(not(target_arch = "x86_64"))]
                let matches_counter = false;
                if matches_counter
                    && event.enabled.load(Ordering::Acquire)
                    && event.target_task == task
                {
                    if deferred_lost != 0 {
                        event
                            .sample_lost
                            .fetch_add(deferred_lost, Ordering::Relaxed);
                    }
                    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
                    notify |= event.sample_record(ip, pid, task as u32, now);
                }
            }
        }
        pending.state.store(0, Ordering::Release);
    }
    if notify {
        narf_net::readiness::notify(0);
    }
}

pub(crate) fn sample_from_irq_for_test(task: u64, ip: u64) {
    let now = narf_time::monotonic_ns();
    let registry = PERF_EVENT_REGISTRY.lock();
    for weak in registry.iter() {
        let Some(event) = weak.upgrade() else {
            continue;
        };
        if event.enabled.load(Ordering::Acquire) && event.target_task == task {
            let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
            let _ = event.sample_record(ip, pid, task as u32, now);
        }
    }
}

impl Drop for PerfEventFile {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: releasing the counter we allocated.
            unsafe {
                narf_arch::x86_64::pmu::release(counter);
            }
        }
        if self.registered.load(Ordering::Acquire)
            && ACTIVE_PERF_EVENTS.fetch_sub(1, Ordering::Relaxed) == 1
        {
            narf_lib::perf::set_enabled(false);
        }
    }
}

impl FileOps for PerfEventFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (value, time_enabled) = self.snapshot();
            let format = self.attr.read_format;
            let mut cursor = 0;

            if format & PERF_FORMAT_GROUP != 0 {
                let members = self.member_files();
                Self::push_word(buf, &mut cursor, 1 + members.len() as u64)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, 0)?;
                }
                for file in members {
                    let event = file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<PerfEventFile>())
                        .ok_or(FsError::InvalidData)?;
                    let (member_value, _) = event.snapshot();
                    Self::push_word(buf, &mut cursor, member_value)?;
                    if format & PERF_FORMAT_ID != 0 {
                        Self::push_word(buf, &mut cursor, event.id)?;
                    }
                    if format & PERF_FORMAT_LOST != 0 {
                        Self::push_word(buf, &mut cursor, 0)?;
                    }
                }
            } else {
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, 0)?;
                }
            }
            Ok(cursor)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            PERF_EVENT_IOC_ENABLE => {
                self.for_group(arg, PerfEventFile::enable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.for_group(arg, PerfEventFile::disable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.for_group(arg, PerfEventFile::reset)?;
                Ok(0)
            }
            PERF_EVENT_IOC_ID => {
                // SAFETY: ioctl's user pointer is validated and SMAP-bracketed by
                // copy_to_user; a bad pointer is reported as InvalidData/EINVAL.
                unsafe { copy_to_user(arg as u64, &self.id.to_ne_bytes()) }
                    .map_err(|_| FsError::InvalidData)?;
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if offset != 0 {
            return Err(FsError::InvalidData);
        }

        let frames = {
            let mut slot = self.mmap.lock();
            if let Some(mapping) = slot.as_ref() {
                if mapping.len != len {
                    return Err(FsError::InvalidData);
                }
                mapping.raw_frames()
            } else {
                let mapping = PerfMmap::allocate(len)?;
                let frames = mapping.raw_frames();
                *slot = Some(mapping);
                frames
            }
        };
        self.publish_mmap_state();
        Ok(frames)
    }

    fn poll_readiness(&self) -> u32 {
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return 0;
        };
        if mapping.read_u64_acquire(PERF_MMAP_DATA_HEAD_OFFSET)
            != mapping.read_u64_acquire(PERF_MMAP_DATA_TAIL_OFFSET)
        {
            narf_filesystem::POLL_IN
        } else {
            0
        }
    }

    fn readiness_notifies(&self) -> bool {
        true
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

pub fn sys_perf_event_open(ctx: &mut dyn TrapContext) {
    let attr_ptr = ctx.args().arg0;
    let pid = ctx.args().arg1 as i32;
    let cpu = ctx.args().arg2 as i32;
    let group_fd = ctx.args().arg3 as i32;
    let flags = ctx.args().arg4;

    // Reject unknown flags per Linux
    // PERF_FLAG_FD_NO_GROUP = 1, PERF_FLAG_FD_OUTPUT = 2, PERF_FLAG_PID_CGROUP = 4, PERF_FLAG_FD_CLOEXEC = 8
    if (flags & !15) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Redirected output and cgroup attachment require the mmap/sampling and
    // cgroup implementations. Do not silently create a differently scoped event.
    if flags & (2 | 4) != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    let mut attr = PerfEventAttr::default();

    // We need to read the size first (u32 at offset 4).
    let mut size: u32 = 0;
    // SAFETY: getting mutable slice of local size variable
    let size_slice =
        unsafe { core::slice::from_raw_parts_mut(&mut size as *mut u32 as *mut u8, 4) };

    // SAFETY: `size_slice` is a 4-byte view of the local `size` u32 (live for this
    // call); `attr_ptr` is the user-supplied pointer and was checked non-null above.
    // `copy_from_user` validates the user range and SMAP-brackets the read, so a bad
    // user address yields Err rather than faulting the kernel.
    if unsafe { copy_from_user(size_slice, attr_ptr + 4) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    if size == 0 {
        size = PERF_ATTR_SIZE_VER0;
    }

    if !(PERF_ATTR_SIZE_VER0..=4096).contains(&size) {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
        return;
    }

    // Read the attr structure
    let to_read = core::cmp::min(size as usize, core::mem::size_of::<PerfEventAttr>());

    // Since PerfEventAttr has padding/not perfectly transparent, we read bytes
    // SAFETY: `attr` is a live local `PerfEventAttr`; we form a byte view spanning
    // exactly its `size_of` so the slice stays within the object. It is only used as
    // the destination of `copy_from_user` below, which writes at most `to_read` bytes.
    let attr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut _ as *mut u8,
            core::mem::size_of::<PerfEventAttr>(),
        )
    };

    // SAFETY: `attr_bytes[..to_read]` is a sub-slice of the live `attr` byte view
    // (`to_read <= size_of::<PerfEventAttr>()`); `attr_ptr` is the non-null user
    // pointer. `copy_from_user` validates the user range and SMAP-brackets the read.
    if unsafe { copy_from_user(&mut attr_bytes[..to_read], attr_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    // If user passed a larger struct, the extra bytes must be zero
    if size as usize > core::mem::size_of::<PerfEventAttr>() {
        let mut extra_byte: u8 = 0;
        for i in core::mem::size_of::<PerfEventAttr>()..(size as usize) {
            let extra_slice = core::slice::from_mut(&mut extra_byte);
            // SAFETY: `extra_slice` is a 1-byte view of the live local `extra_byte`;
            // `attr_ptr + i` stays within the user-declared `size` window (i < size).
            // `copy_from_user` validates the user range and SMAP-brackets the read.
            if unsafe { copy_from_user(extra_slice, attr_ptr + i as u64) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            if extra_byte != 0 {
                ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
                return;
            }
        }
    }

    if attr.__reserved_2 != 0 || attr.__reserved_3 != 0 || attr.config3 != 0 || attr.config4 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if attr.read_format & !PERF_FORMAT_SUPPORTED != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    // Every accepted attribute bit must have its Linux meaning. In particular,
    // frequency mode needs a feedback controller and exclude/inherit/metadata
    // bits need scheduler/process integration; ignoring them would fabricate
    // compatibility.
    if attr.flags & !PERF_ATTR_IMPLEMENTED != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr.sample_period_or_freq != 0
        && (attr.sample_type == 0 || attr.sample_type & !PERF_SAMPLE_SUPPORTED != 0)
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if !is_supported_event(&attr) {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    let task = current_task_id();

    let target_task = if pid == 0 {
        task
    } else if pid > 0 {
        match crate::handlers::pid_to_task_raw(pid as u64) {
            Some(target) => target,
            None if pid as u64 == task => task,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    } else {
        // pid == -1 denotes a per-CPU event with no task target.
        u64::MAX
    };
    let target_pid = if pid == 0 {
        crate::handlers::task_to_pid_raw(task).unwrap_or(task)
    } else if pid > 0 {
        pid as u64
    } else {
        u64::MAX
    };

    if cpu != -1 && (cpu < 0 || !narf_lib::smp::is_online(cpu as u32)) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if pid == -1 && cpu == -1 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if attr.type_ != PERF_TYPE_SOFTWARE
        && (pid != -1
            || cpu != narf_lib::percpu::current_cpu() as i32
            || narf_lib::smp::online_count() != 1)
    {
        // Hardware counters are per-CPU. Until scheduler context switching
        // and remote-CPU PMU calls exist, admitting a task event or an SMP
        // event would count unrelated execution or access another CPU's MSRs.
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    let group_leader = if group_fd != -1 {
        let leader =
            fd::with_table(task, |t| t.get(group_fd as u32).map(|e| Arc::clone(&e.ops))).flatten();
        let Some(leader) = leader else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        let Some(leader_event) = leader
            .as_any()
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
        else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        if leader_event.target_task != target_task || leader_event.target_cpu != cpu {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        Some(leader)
    } else {
        None
    };

    // Try to allocate PMU counter if target_arch is x86_64
    #[cfg(target_arch = "x86_64")]
    let pmu_counter = {
        let event_opt = match attr.type_ {
            // PERF_TYPE_HARDWARE
            PERF_TYPE_HARDWARE => match attr.config {
                PERF_COUNT_HW_CPU_CYCLES => Some(narf_arch::x86_64::pmu::PmuEvent::Cycles),
                PERF_COUNT_HW_INSTRUCTIONS => Some(narf_arch::x86_64::pmu::PmuEvent::Instructions),
                PERF_COUNT_HW_CACHE_MISSES => Some(narf_arch::x86_64::pmu::PmuEvent::LlcMisses),
                PERF_COUNT_HW_BRANCH_INSTRUCTIONS => {
                    Some(narf_arch::x86_64::pmu::PmuEvent::BranchInstructions)
                }
                PERF_COUNT_HW_BRANCH_MISSES => Some(narf_arch::x86_64::pmu::PmuEvent::BranchMisses),
                _ => None,
            },
            // PERF_TYPE_HW_CACHE
            PERF_TYPE_HW_CACHE => {
                let cache_id = attr.config & 0xFF;
                let op_id = (attr.config >> 8) & 0xFF;
                let result_id = (attr.config >> 16) & 0xFF;
                match (cache_id, op_id, result_id) {
                    (
                        PERF_COUNT_HW_CACHE_LL,
                        PERF_COUNT_HW_CACHE_OP_READ,
                        PERF_COUNT_HW_CACHE_RESULT_MISS,
                    ) => Some(narf_arch::x86_64::pmu::PmuEvent::LlcMisses),
                    _ => None,
                }
            }
            // PERF_TYPE_RAW
            PERF_TYPE_RAW => Some(narf_arch::x86_64::pmu::PmuEvent::Raw(
                attr.config | (1 << 16) | (1 << 17),
            )),
            _ => None,
        };

        if let Some(event) = event_opt {
            // SAFETY: alloc_counter programs PMU hardware registers, which requires CPL=0.
            match unsafe { narf_arch::x86_64::pmu::alloc_counter(event) } {
                Ok(counter) => Some(counter),
                Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                    ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                    return;
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
                    return;
                }
            }
        } else if attr.type_ == PERF_TYPE_SOFTWARE {
            None
        } else {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
            return;
        }
    };

    #[cfg(not(target_arch = "x86_64"))]
    if attr.type_ != PERF_TYPE_SOFTWARE {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    #[cfg(target_arch = "x86_64")]
    let sample_period = if attr.sample_period_or_freq != 0 {
        let Some(counter) = pmu_counter.as_ref() else {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
            return;
        };
        let period = attr.sample_period_or_freq;
        if ensure_pmi_route().is_err() {
            // SAFETY: open still exclusively owns this allocation.
            unsafe { narf_arch::x86_64::pmu::release(*counter) };
            ctx.set_return(SyscallReturn::ok((-95i64) as u64));
            return;
        }
        // Validate the period and counter backend now. Keep the event paused
        // until ENABLE/enable_on_exec establishes the requested time window.
        // SAFETY: this open path owns the freshly allocated live counter.
        let armed = unsafe { narf_arch::x86_64::pmu::arm_sampling(counter, period) };
        if armed.is_err() {
            // SAFETY: open still exclusively owns this allocation.
            unsafe { narf_arch::x86_64::pmu::release(*counter) };
            ctx.set_return(SyscallReturn::ok((-95i64) as u64));
            return;
        }
        // SAFETY: same live counter; restore non-interrupt counting state.
        let _ = unsafe { narf_arch::x86_64::pmu::pause_sampling(counter) };
        period
    } else {
        0
    };

    #[cfg(not(target_arch = "x86_64"))]
    if attr.sample_period_or_freq != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
        return;
    }

    // Allocate an fd
    let cloexec = (flags & 8) != 0; // PERF_FLAG_FD_CLOEXEC
    let install_flags = if cloexec { fd::FD_CLOEXEC } else { 0 };

    let mut opened_file = None;
    let fd_num_opt = fd::with_table(task, |t| {
        // A group member is scheduled only through its leader even when its
        // own disabled bit is clear (the upstream CLI relies on this).
        let initially_enabled = group_leader.is_none() && attr.flags & PERF_ATTR_FLAG_DISABLED == 0;
        let file = Arc::new(PerfEventFile {
            attr,
            id: NEXT_PERF_EVENT_ID.fetch_add(1, Ordering::Relaxed),
            target_task,
            target_pid,
            target_cpu: cpu,
            enabled: AtomicBool::new(false),
            count_base: AtomicU64::new(0),
            count_accumulated: AtomicU64::new(0),
            enabled_at_ns: AtomicU64::new(0),
            time_enabled_ns: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            sample_lost: AtomicU64::new(0),
            #[cfg(target_arch = "x86_64")]
            sample_period,
            mmap_seq: AtomicU32::new(0),
            mmap: IrqSafeSpinLock::new(None),
            group_members: IrqSafeSpinLock::new(Vec::new()),
            _group_leader: group_leader.clone(),
            #[cfg(target_arch = "x86_64")]
            pmu_counter,
        });
        if initially_enabled {
            file.enable();
        }
        let ops: Arc<dyn FileOps> = file.clone();
        if let Some(leader) = &group_leader {
            if let Some(event) = leader
                .as_any()
                .and_then(|any| any.downcast_ref::<PerfEventFile>())
            {
                event.add_group_member(&ops);
            }
        }
        let result = t.open(FdEntry {
            ops,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        });
        opened_file = Some(file);
        result
    });

    if let Some(fd_num) = fd_num_opt {
        // Mark registration before publishing the global enabled bit. The fd table
        // owns another Arc, so this file remains alive after `opened_file` drops.
        if let Some(file) = opened_file {
            file.registered.store(true, Ordering::Release);
            PERF_EVENT_REGISTRY.lock().push(Arc::downgrade(&file));
        }
        if ACTIVE_PERF_EVENTS.fetch_add(1, Ordering::Relaxed) == 0 {
            narf_lib::perf::set_enabled(true);
        }
        ctx.set_return(SyscallReturn::ok(fd_num as u64));
    } else {
        // No fd table exists for the current task, so the closure never took
        // ownership of the allocated counter.
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = pmu_counter {
            // SAFETY: this is the counter allocated above and no file owns it.
            unsafe {
                narf_arch::x86_64::pmu::release(counter);
            }
        }
        ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // EMFILE
    }
}

fn is_supported_event(attr: &PerfEventAttr) -> bool {
    match attr.type_ {
        // PERF_TYPE_HARDWARE
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_HARDWARE => matches!(
            attr.config,
            PERF_COUNT_HW_CPU_CYCLES
                | PERF_COUNT_HW_INSTRUCTIONS
                | PERF_COUNT_HW_CACHE_MISSES
                | PERF_COUNT_HW_BRANCH_INSTRUCTIONS
                | PERF_COUNT_HW_BRANCH_MISSES
        ),
        // PERF_TYPE_SOFTWARE
        PERF_TYPE_SOFTWARE => attr.config == PERF_COUNT_SW_DUMMY,
        // PERF_TYPE_HW_CACHE (3)
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_HW_CACHE => {
            let cache_id = attr.config & 0xFF;
            let op_id = (attr.config >> 8) & 0xFF;
            let result_id = (attr.config >> 16) & 0xFF;
            (cache_id, op_id, result_id)
                == (
                    PERF_COUNT_HW_CACHE_LL,
                    PERF_COUNT_HW_CACHE_OP_READ,
                    PERF_COUNT_HW_CACHE_RESULT_MISS,
                )
        }
        // PERF_TYPE_RAW (4)
        #[cfg(target_arch = "x86_64")]
        PERF_TYPE_RAW => true,
        _ => false,
    }
}
