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
    PerfEventAttr, PERF_ATTR_FLAG_BPF_EVENT, PERF_ATTR_FLAG_COMM, PERF_ATTR_FLAG_COMM_EXEC,
    PERF_ATTR_FLAG_DISABLED, PERF_ATTR_FLAG_ENABLE_ON_EXEC, PERF_ATTR_FLAG_EXCLUDE_GUEST,
    PERF_ATTR_FLAG_FREQ, PERF_ATTR_FLAG_INHERIT, PERF_ATTR_FLAG_KSYMBOL, PERF_ATTR_FLAG_MMAP,
    PERF_ATTR_FLAG_MMAP2, PERF_ATTR_FLAG_MMAP_DATA, PERF_ATTR_FLAG_SAMPLE_ID_ALL,
    PERF_ATTR_FLAG_TASK, PERF_ATTR_FLAG_WATERMARK, PERF_ATTR_SIZE_VER0, PERF_COUNT_SW_DUMMY,
    PERF_FORMAT_GROUP, PERF_FORMAT_ID, PERF_FORMAT_LOST, PERF_FORMAT_TOTAL_TIME_ENABLED,
    PERF_FORMAT_TOTAL_TIME_RUNNING, PERF_RECORD_COMM, PERF_RECORD_EXIT, PERF_RECORD_FORK,
    PERF_RECORD_LOST, PERF_RECORD_MISC_COMM_EXEC, PERF_RECORD_MISC_MMAP_DATA, PERF_RECORD_MMAP,
    PERF_RECORD_MMAP2, PERF_RECORD_SAMPLE, PERF_SAMPLE_CPU, PERF_SAMPLE_ID, PERF_SAMPLE_IDENTIFIER,
    PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD, PERF_SAMPLE_STREAM_ID, PERF_SAMPLE_TID, PERF_SAMPLE_TIME,
    PERF_TYPE_SOFTWARE,
};
#[cfg(target_arch = "x86_64")]
use narf_linux_perf_uapi::{
    PERF_COUNT_HW_BRANCH_INSTRUCTIONS, PERF_COUNT_HW_BRANCH_MISSES, PERF_COUNT_HW_CACHE_LL,
    PERF_COUNT_HW_CACHE_MISSES, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS,
    PERF_COUNT_HW_CPU_CYCLES, PERF_COUNT_HW_INSTRUCTIONS, PERF_TYPE_HARDWARE, PERF_TYPE_HW_CACHE,
    PERF_TYPE_RAW,
};

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);
static PERF_EVENT_REGISTRY: IrqSafeSpinLock<Vec<Weak<PerfEventFile>>> =
    IrqSafeSpinLock::new(Vec::new());
#[cfg(target_arch = "x86_64")]
static PMI_VECTOR: IrqSafeSpinLock<Option<u8>> = IrqSafeSpinLock::new(None);
#[cfg(target_arch = "x86_64")]
static PMI_ROUTED_CPUS: AtomicU64 = AtomicU64::new(0);
const SAMPLE_CPU_SLOTS: usize = narf_lib::percpu::MAX_CPUS;
static PENDING_SAMPLES: [PendingSample; SAMPLE_CPU_SLOTS] =
    [const { PendingSample::new() }; SAMPLE_CPU_SLOTS];
static PENDING_SAMPLE_LOST: AtomicU64 = AtomicU64::new(0);
#[cfg(target_arch = "x86_64")]
static ACTIVE_SAMPLE_IDS: [[AtomicU64; 8]; SAMPLE_CPU_SLOTS] =
    [const { [const { AtomicU64::new(0) }; 8] }; SAMPLE_CPU_SLOTS];

#[cfg(target_arch = "x86_64")]
pub(crate) fn frequency_period(current: u64, frequency: u64, elapsed_ns: u64) -> u64 {
    let current = current.max(1);
    let target_ns = 1_000_000_000u64
        .checked_div(frequency.max(1))
        .unwrap_or(1)
        .max(1);
    let calculated = (current as u128)
        .saturating_mul(target_ns as u128)
        .checked_div(elapsed_ns.max(1) as u128)
        .unwrap_or(1)
        .min(u64::MAX as u128) as u64;
    calculated
        .clamp((current / 4).max(1), current.saturating_mul(4))
        .max(1)
}

struct PendingSample {
    state: AtomicU8,
    task: AtomicU64,
    ip: AtomicU64,
    time: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    counters: AtomicU8,
    #[cfg(target_arch = "x86_64")]
    event_ids: [AtomicU64; 8],
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
            #[cfg(target_arch = "x86_64")]
            event_ids: [const { AtomicU64::new(0) }; 8],
        }
    }
}

const PERF_FORMAT_SUPPORTED: u64 = (1 << 5) - 1;

const PERF_ATTR_IMPLEMENTED: u64 = PERF_ATTR_FLAG_DISABLED
    | PERF_ATTR_FLAG_ENABLE_ON_EXEC
    | PERF_ATTR_FLAG_COMM
    | PERF_ATTR_FLAG_TASK
    | PERF_ATTR_FLAG_SAMPLE_ID_ALL
    | PERF_ATTR_FLAG_COMM_EXEC
    | PERF_ATTR_FLAG_MMAP
    | PERF_ATTR_FLAG_MMAP_DATA
    | PERF_ATTR_FLAG_MMAP2
    | PERF_ATTR_FLAG_FREQ
    | PERF_ATTR_FLAG_INHERIT
    // NARF does not execute nested guests and currently has no BPF VM or
    // runtime kernel-symbol loader. These selectors therefore describe empty
    // event domains, rather than requests whose records are being suppressed.
    | PERF_ATTR_FLAG_EXCLUDE_GUEST
    | PERF_ATTR_FLAG_KSYMBOL
    | PERF_ATTR_FLAG_BPF_EVENT;

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
    inherited_tasks: IrqSafeSpinLock<Vec<u64>>,
    enabled: AtomicBool,
    count_base: AtomicU64,
    count_accumulated: AtomicU64,
    enabled_at_ns: AtomicU64,
    time_enabled_ns: AtomicU64,
    registered: AtomicBool,
    sample_lost: AtomicU64,
    wakeup_pending: AtomicU32,
    #[cfg(target_arch = "x86_64")]
    sample_period: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    last_sample_period: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    sample_frequency: u64,
    #[cfg(target_arch = "x86_64")]
    last_sample_ns: AtomicU64,
    #[cfg(target_arch = "x86_64")]
    pmu_event: Option<narf_arch::x86_64::pmu::PmuEvent>,
    #[cfg(target_arch = "x86_64")]
    active_task_counters:
        IrqSafeSpinLock<[Option<narf_arch::x86_64::pmu::PmuCounter>; narf_lib::percpu::MAX_CPUS]>,
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
    fn tracks_task(&self, task: u64) -> bool {
        self.target_task == task || self.inherited_tasks.lock().contains(&task)
    }

    fn raw_count(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: the counter belongs to this open file and remains allocated
            // until Drop, which cannot run while this method borrows `self`.
            return unsafe { narf_arch::x86_64::pmu::read(&counter) };
        }
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu] {
                // SAFETY: this entry can only be populated while its target is
                // executing on this CPU; syscall reads run in that continuation.
                return unsafe { narf_arch::x86_64::pmu::read(&counter) };
            }
        }

        // PERF_COUNT_SW_DUMMY is the only software event admitted until
        // scheduler-owned, per-target software accounting exists. Its specified
        // count is exactly zero.
        0
    }

    #[cfg(target_arch = "x86_64")]
    fn task_switch(&self, cpu: usize, running: bool) {
        if self.target_task == u64::MAX || self.pmu_event.is_none() {
            return;
        }
        let mut active = self.active_task_counters.lock();
        if self.target_cpu >= 0 && cpu != self.target_cpu as usize {
            return;
        }
        if running {
            if active[cpu].is_some() || !self.enabled.load(Ordering::Acquire) {
                return;
            }
            // SAFETY: the scheduler invokes this on the current logical CPU in
            // executor context. The returned slot belongs to this CPU.
            let Ok(counter) =
                (unsafe { narf_arch::x86_64::pmu::alloc_counter(self.pmu_event.unwrap()) })
            else {
                return;
            };
            let sample_period = self.sample_period.load(Ordering::Acquire);
            if sample_period != 0 {
                if ensure_pmi_route().is_err() {
                    // SAFETY: same current-CPU allocation.
                    unsafe { narf_arch::x86_64::pmu::release(counter) };
                    return;
                }
                // SAFETY: freshly allocated current-CPU counter.
                if unsafe { narf_arch::x86_64::pmu::arm_sampling(&counter, sample_period) }.is_err()
                {
                    // SAFETY: same current-CPU allocation.
                    unsafe { narf_arch::x86_64::pmu::release(counter) };
                    return;
                }
                ACTIVE_SAMPLE_IDS[cpu][counter.idx as usize].store(self.id, Ordering::Release);
            }
            active[cpu] = Some(counter);
        } else if let Some(counter) = active[cpu].take() {
            let sample_period = self.sample_period.load(Ordering::Acquire);
            if sample_period != 0 {
                ACTIVE_SAMPLE_IDS[cpu][counter.idx as usize].store(0, Ordering::Release);
                // SAFETY: current-CPU live allocation.
                let _ = unsafe { narf_arch::x86_64::pmu::pause_sampling(&counter) };
            }
            // SAFETY: current-CPU live allocation.
            let value = if sample_period == 0 {
                // SAFETY: current-CPU live allocation.
                unsafe { narf_arch::x86_64::pmu::read(&counter) }
            } else {
                // SAFETY: current-CPU sampled allocation.
                unsafe { narf_arch::x86_64::pmu::sampling_residual(&counter, sample_period) }
                    .unwrap_or(0)
            };
            self.count_accumulated.fetch_add(value, Ordering::AcqRel);
            // SAFETY: current-CPU live allocation.
            unsafe { narf_arch::x86_64::pmu::release(counter) };
        }
    }

    fn enable(&self) {
        if !self.enabled.swap(true, Ordering::AcqRel) {
            let raw = self.raw_count();
            let now = narf_time::monotonic_ns();
            self.count_base.store(raw, Ordering::Release);
            self.enabled_at_ns.store(now, Ordering::Release);
            #[cfg(target_arch = "x86_64")]
            {
                self.last_sample_ns.store(0, Ordering::Release);
                let sample_period = self.sample_period.load(Ordering::Acquire);
                if sample_period != 0 {
                    if let Some(counter) = &self.pmu_counter {
                        // SAFETY: this file owns the live counter.
                        let _ =
                            unsafe { narf_arch::x86_64::pmu::arm_sampling(counter, sample_period) };
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            if self.tracks_task(crate::handlers::current_task_id()) {
                self.task_switch(narf_lib::percpu::current_cpu(), true);
            }
        }
        self.publish_mmap_state();
    }

    fn disable(&self) {
        if self.enabled.swap(false, Ordering::AcqRel) {
            #[cfg(target_arch = "x86_64")]
            if self.tracks_task(crate::handlers::current_task_id()) {
                self.task_switch(narf_lib::percpu::current_cpu(), false);
            }
            #[cfg(target_arch = "x86_64")]
            if self.sample_period.load(Ordering::Acquire) != 0 {
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
        let threshold = self.attr.wakeup_events_or_watermark;
        if threshold != 0
            && self
                .wakeup_pending
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1)
                >= threshold
        {
            self.wakeup_pending.store(0, Ordering::Release);
            narf_net::readiness::notify(0);
        }
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
            #[cfg(target_arch = "x86_64")]
            push_u64(
                &mut payload,
                self.last_sample_period.load(Ordering::Acquire),
            );
            #[cfg(not(target_arch = "x86_64"))]
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

    #[cfg(target_arch = "x86_64")]
    fn adjust_frequency_period(&self, now: u64) {
        if self.sample_frequency == 0 {
            return;
        }
        let previous = self.last_sample_ns.swap(now, Ordering::AcqRel);
        if previous == 0 {
            return;
        }
        let elapsed = now.saturating_sub(previous).max(1);
        let current = self.sample_period.load(Ordering::Acquire).max(1);
        // Linux derives the next hardware period from observed event count
        // over elapsed time. Bound each correction to 4x so scheduler jitter
        // or a delayed drain cannot collapse the period into an IRQ storm.
        let next = frequency_period(current, self.sample_frequency, elapsed);
        self.sample_period.store(next, Ordering::Release);
        if let Some(counter) = &self.pmu_counter {
            narf_arch::x86_64::pmu::update_sampling_period(counter, next);
        }
        for counter in self.active_task_counters.lock().iter().flatten() {
            narf_arch::x86_64::pmu::update_sampling_period(counter, next);
        }
    }

    fn append_sample_id(&self, record: &mut Vec<u8>, pid: u32, tid: u32, now: u64) {
        if self.attr.flags & PERF_ATTR_FLAG_SAMPLE_ID_ALL == 0 {
            return;
        }
        if self.attr.sample_type & PERF_SAMPLE_TID != 0 {
            record.extend_from_slice(&pid.to_ne_bytes());
            record.extend_from_slice(&tid.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_TIME != 0 {
            record.extend_from_slice(&now.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_ID != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_STREAM_ID != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_CPU != 0 {
            record.extend_from_slice(&(narf_lib::percpu::current_cpu() as u32).to_ne_bytes());
            record.extend_from_slice(&0u32.to_ne_bytes());
        }
        if self.attr.sample_type & PERF_SAMPLE_IDENTIFIER != 0 {
            record.extend_from_slice(&self.id.to_ne_bytes());
        }
    }

    fn finish_record(record: &mut [u8], misc: u16) -> bool {
        let Ok(size) = u16::try_from(record.len()) else {
            return false;
        };
        record[4..6].copy_from_slice(&misc.to_ne_bytes());
        record[6..8].copy_from_slice(&size.to_ne_bytes());
        true
    }

    fn comm_record(&self, pid: u32, tid: u32, comm: &str, exec: bool) -> bool {
        let mut record = Vec::with_capacity(64);
        record.extend_from_slice(&PERF_RECORD_COMM.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&pid.to_ne_bytes());
        record.extend_from_slice(&tid.to_ne_bytes());
        record.extend_from_slice(comm.as_bytes());
        record.push(0);
        while record.len() & 7 != 0 {
            record.push(0);
        }
        self.append_sample_id(&mut record, pid, tid, narf_time::monotonic_ns());
        let misc = if exec && self.attr.flags & PERF_ATTR_FLAG_COMM_EXEC != 0 {
            PERF_RECORD_MISC_COMM_EXEC
        } else {
            0
        };
        Self::finish_record(&mut record, misc) && self.push_record(&record)
    }

    fn task_record(&self, record_type: u32, pid: u32, ppid: u32, tid: u32, ptid: u32) -> bool {
        let now = narf_time::monotonic_ns();
        let mut record = Vec::with_capacity(64);
        record.extend_from_slice(&record_type.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&pid.to_ne_bytes());
        record.extend_from_slice(&ppid.to_ne_bytes());
        record.extend_from_slice(&tid.to_ne_bytes());
        record.extend_from_slice(&ptid.to_ne_bytes());
        record.extend_from_slice(&now.to_ne_bytes());
        self.append_sample_id(&mut record, pid, tid, now);
        Self::finish_record(&mut record, 0) && self.push_record(&record)
    }

    fn mmap_record(&self, mapping: &PerfMapping<'_>) -> bool {
        let executable = mapping.prot & 4 != 0;
        if (executable && self.attr.flags & (PERF_ATTR_FLAG_MMAP | PERF_ATTR_FLAG_MMAP2) == 0)
            || (!executable && self.attr.flags & PERF_ATTR_FLAG_MMAP_DATA == 0)
        {
            return false;
        }

        let mmap2 = self.attr.flags & PERF_ATTR_FLAG_MMAP2 != 0;
        let record_type = if mmap2 {
            PERF_RECORD_MMAP2
        } else {
            PERF_RECORD_MMAP
        };
        let now = narf_time::monotonic_ns();
        let mut record = Vec::with_capacity(96);
        record.extend_from_slice(&record_type.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&0u16.to_ne_bytes());
        record.extend_from_slice(&mapping.pid.to_ne_bytes());
        record.extend_from_slice(&mapping.tid.to_ne_bytes());
        record.extend_from_slice(&mapping.addr.to_ne_bytes());
        record.extend_from_slice(&mapping.len.to_ne_bytes());
        record.extend_from_slice(&mapping.pgoff.to_ne_bytes());
        if mmap2 {
            // NARF currently has one VFS device namespace (dev 0:0) and no
            // inode-generation counter. `ino` is the backing FileOps' stable
            // filesystem identity, or zero for an anonymous/synthetic map.
            record.extend_from_slice(&0u32.to_ne_bytes());
            record.extend_from_slice(&0u32.to_ne_bytes());
            record.extend_from_slice(&mapping.ino.to_ne_bytes());
            record.extend_from_slice(&0u64.to_ne_bytes());
            record.extend_from_slice(&mapping.prot.to_ne_bytes());
            record.extend_from_slice(&mapping.flags.to_ne_bytes());
        }
        record.extend_from_slice(mapping.filename.as_bytes());
        record.push(0);
        while record.len() & 7 != 0 {
            record.push(0);
        }
        self.append_sample_id(&mut record, mapping.pid, mapping.tid, now);
        let misc = if executable {
            0
        } else {
            PERF_RECORD_MISC_MMAP_DATA
        };
        Self::finish_record(&mut record, misc) && self.push_record(&record)
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

struct PerfMapping<'a> {
    pid: u32,
    tid: u32,
    addr: u64,
    len: u64,
    pgoff: u64,
    ino: u64,
    prot: u32,
    flags: u32,
    filename: &'a str,
}

/// Apply Linux `enable_on_exec` at the point a task commits a new image.
///
/// Events are owned by the monitoring process but keyed by the target task,
/// matching the way the upstream perf CLI opens events for its stopped child.
pub(crate) fn on_exec(task: u64, mappings: &[crate::process::LoadedMapping], program_path: &str) {
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let comm = crate::handlers::proc_comm_of(task);
    let resolved: Vec<(&crate::process::LoadedMapping, &str, u64)> = mappings
        .iter()
        .map(|mapping| {
            let filename = mapping.filename.as_deref().unwrap_or(program_path);
            let ino = if filename.starts_with('[') {
                0
            } else {
                let path = crate::handlers::apply_chroot(filename);
                narf_filesystem::registry()
                    .resolve_absolute(&path, |fs, rel| {
                        crate::handlers::poll_blocking(narf_filesystem::resolve_async(
                            fs.root(),
                            rel,
                        ))
                    })
                    .and_then(|result| result)
                    .and_then(Result::ok)
                    .map(|ops| ops.ino())
                    .unwrap_or(0)
            };
            (mapping, filename, ino)
        })
        .collect();
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task)
            && event.attr.flags & PERF_ATTR_FLAG_ENABLE_ON_EXEC != 0
            && event._group_leader.is_none()
        {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::enable);
        }
        if event.tracks_task(task) {
            for (loaded, filename, ino) in &resolved {
                let mapping = PerfMapping {
                    pid: pid as u32,
                    tid: task as u32,
                    addr: loaded.addr,
                    len: loaded.len,
                    pgoff: loaded.pgoff,
                    ino: *ino,
                    prot: loaded.prot,
                    flags: 2, // loader VMAs are MAP_PRIVATE
                    filename,
                };
                let _ = event.mmap_record(&mapping);
            }
        }
        if event.tracks_task(task) && event.attr.flags & PERF_ATTR_FLAG_COMM != 0 {
            if let Some(comm) = comm.as_deref() {
                let _ = event.comm_record(pid as u32, task as u32, comm, true);
            }
        }
        true
    });
}

pub(crate) fn on_comm(task: u64, comm: &str) {
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) && event.attr.flags & PERF_ATTR_FLAG_COMM != 0 {
            let _ = event.comm_record(pid as u32, task as u32, comm, false);
        }
        true
    });
}

/// Publish a mapping only after its PTE materialization has committed.
pub(crate) fn on_mmap(task: u64, fd: i32, addr: u64, len: u64, pgoff: u64, prot: u32, flags: u32) {
    const MAP_SHARED: u32 = 0x01;
    const MAP_PRIVATE: u32 = 0x02;
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let file = if fd >= 0 {
        fd::with_table(task, |table| {
            table
                .get(fd as u32)
                .map(|entry| (entry.ops.ino(), crate::mqueue::fd_path(task, fd as u32)))
        })
        .flatten()
    } else {
        None
    };
    let (ino, filename) = match file {
        Some((ino, Some(path))) => (ino, path),
        Some((ino, None)) => (ino, alloc::string::String::from("//unknown")),
        None => (0, alloc::string::String::from("//anon")),
    };
    let mapping = PerfMapping {
        pid: pid as u32,
        tid: task as u32,
        addr,
        len,
        pgoff,
        ino,
        prot,
        // Linux records VMA semantics, not transient mmap request controls
        // such as MAP_FIXED or MAP_ANONYMOUS.
        flags: if flags & MAP_SHARED != 0 {
            MAP_SHARED
        } else {
            MAP_PRIVATE
        },
        filename: &filename,
    };
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) {
            let _ = event.mmap_record(&mapping);
        }
        true
    });
}

pub(crate) fn on_fork(parent_pid: u64, child_pid: u64, parent_tid: u64, child_tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        let inherits_parent = event.tracks_task(parent_tid);
        if inherits_parent && event.attr.flags & PERF_ATTR_FLAG_INHERIT != 0 {
            let mut inherited = event.inherited_tasks.lock();
            if !inherited.contains(&child_tid) {
                inherited.push(child_tid);
            }
        }
        if inherits_parent && event.attr.flags & PERF_ATTR_FLAG_TASK != 0 {
            let _ = event.task_record(
                PERF_RECORD_FORK,
                child_pid as u32,
                parent_pid as u32,
                child_tid as u32,
                parent_tid as u32,
            );
        }
        true
    });
}

/// Stop task-targeted events when the target process becomes group-dead.
pub(crate) fn on_process_exit(pid: u64, tid: u64) {
    let parent_pid = crate::handlers::parent_of_get(pid).unwrap_or(0);
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_pid == pid {
            if event.attr.flags & PERF_ATTR_FLAG_TASK != 0 {
                let _ = event.task_record(
                    PERF_RECORD_EXIT,
                    pid as u32,
                    parent_pid as u32,
                    tid as u32,
                    parent_pid as u32,
                );
            }
            if event._group_leader.is_none() {
                let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::disable);
            }
        }
        true
    });
}

pub(crate) fn on_thread_exit(_pid: u64, tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        event.inherited_tasks.lock().retain(|task| *task != tid);
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
    for (idx, event_id) in pending.event_ids.iter().enumerate() {
        if counters & (1 << idx) != 0 {
            event_id.store(
                ACTIVE_SAMPLE_IDS[cpu][idx].load(Ordering::Acquire),
                Ordering::Relaxed,
            );
        }
    }
    pending.state.store(2, Ordering::Release);
    // Wake a parked poll/epoll task so its syscall re-enters normal context
    // and drains this allocation-free IRQ snapshot into the mmap ring.
    narf_net::readiness::notify(0);
    narf_interrupts::IrqStatus::Handled
}

#[cfg(target_arch = "x86_64")]
fn ensure_pmi_route() -> Result<(), ()> {
    let mut slot = PMI_VECTOR.lock();
    let vector = if let Some(vector) = *slot {
        vector
    } else {
        let vector = narf_interrupts::vector::alloc().map_err(|_| ())?;
        narf_interrupts::install_handler_named(vector, "perf-pmi", 0, pmi_handler);
        *slot = Some(vector);
        vector
    };
    drop(slot);
    let cpu = narf_lib::percpu::current_cpu();
    let cpu_bit = 1u64.checked_shl(cpu as u32).ok_or(())?;
    if PMI_ROUTED_CPUS.fetch_or(cpu_bit, Ordering::AcqRel) & cpu_bit != 0 {
        return Ok(());
    }
    // SAFETY: APIC bring-up precedes userspace and this programs only the
    // current CPU's LVT-PC entry.
    unsafe { narf_arch::x86_64::pmi::program_current_lvt_pc(vector, false) };
    Ok(())
}

/// Drain allocation-free PMI snapshots into userspace mmap rings from normal
/// syscall context. The IRQ handler captures IP/task/time and rearms hardware;
/// record encoding and readiness wakeups happen here where allocation is safe.
pub(crate) fn drain_irq_samples() {
    let mut notify = false;
    let deferred_lost = PENDING_SAMPLE_LOST.swap(0, Ordering::AcqRel);
    for (_source_cpu, pending) in PENDING_SAMPLES.iter().enumerate() {
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
                let matched_counter = (0..8).find(|&idx| {
                    counters & (1 << idx) != 0
                        && (pending.event_ids[idx].load(Ordering::Relaxed) == event.id
                            || event
                                .pmu_counter
                                .is_some_and(|counter| counter.idx as usize == idx))
                });
                #[cfg(not(target_arch = "x86_64"))]
                let matched_counter: Option<usize> = None;
                if let Some(_matched_counter) = matched_counter {
                    if !event.enabled.load(Ordering::Acquire) || !event.tracks_task(task) {
                        continue;
                    }
                    #[cfg(target_arch = "x86_64")]
                    {
                        let period = narf_arch::x86_64::pmu::last_overflow_period(
                            _source_cpu,
                            _matched_counter,
                        );
                        event.last_sample_period.store(period, Ordering::Release);
                        event.count_accumulated.fetch_add(period, Ordering::AcqRel);
                    }
                    if deferred_lost != 0 {
                        event
                            .sample_lost
                            .fetch_add(deferred_lost, Ordering::Relaxed);
                    }
                    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
                    notify |= event.sample_record(ip, pid, task as u32, now);
                    #[cfg(target_arch = "x86_64")]
                    event.adjust_frequency_period(now);
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
        if event.enabled.load(Ordering::Acquire) && event.tracks_task(task) {
            let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task) as u32;
            let _ = event.sample_record(ip, pid, task as u32, now);
        }
    }
}

pub(crate) fn event_tracks_task_for_test(fd_num: u32, task: u64) -> bool {
    let owner = crate::handlers::current_task_id();
    fd::with_table(owner, |table| {
        table
            .get(fd_num)
            .and_then(|entry| entry.ops.as_any())
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
            .is_some_and(|event| event.tracks_task(task))
    })
    .unwrap_or(false)
}

/// Scheduler PMU context hook. Runs outside scheduler queue locks and brackets
/// the matching task continuation on the current logical CPU.
#[cfg(target_arch = "x86_64")]
pub(crate) fn on_task_switch(task: u64, running: bool) {
    if !narf_lib::perf::enabled() {
        return;
    }
    let cpu = narf_lib::percpu::current_cpu();
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.tracks_task(task) {
            event.task_switch(cpu, running);
        }
        true
    });
}

impl Drop for PerfEventFile {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        {
            let cpu = narf_lib::percpu::current_cpu();
            if let Some(counter) = self.active_task_counters.lock()[cpu].take() {
                // SAFETY: a task can close its own event only while executing
                // on this CPU; no other CPU can simultaneously run that task.
                unsafe { narf_arch::x86_64::pmu::release(counter) };
            }
        }
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
    let unsupported_attr_flags = attr.flags & !PERF_ATTR_IMPLEMENTED;
    let empty_bpf_sideband_dummy = attr.type_ == PERF_TYPE_SOFTWARE
        && attr.config == PERF_COUNT_SW_DUMMY
        && attr.flags & PERF_ATTR_FLAG_BPF_EVENT != 0
        && attr.sample_period_or_freq == 0;
    if unsupported_attr_flags != 0
        && !(unsupported_attr_flags == PERF_ATTR_FLAG_WATERMARK && empty_bpf_sideband_dummy)
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr.sample_period_or_freq != 0
        && (attr.sample_type == 0 || attr.sample_type & !PERF_SAMPLE_SUPPORTED != 0)
    {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_FREQ != 0
        && (attr.sample_period_or_freq == 0 || attr.sample_period_or_freq > 1_000_000)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if attr.flags & PERF_ATTR_FLAG_SAMPLE_ID_ALL != 0
        && attr.sample_type & !PERF_SAMPLE_SUPPORTED != 0
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
        && pid == -1
        && (cpu != narf_lib::percpu::current_cpu() as i32 || narf_lib::smp::online_count() != 1)
    {
        // A per-CPU event requires remote-CPU PMU calls on SMP. Task events are
        // virtualized by the scheduler switch hook below.
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
    let (pmu_event, pmu_counter) = {
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
            if pid != -1 {
                // Validate that this CPU exposes a real backend and mapping.
                // The actual counter is allocated on each task switch-in.
                // SAFETY: syscall context at CPL0 on the current CPU.
                let probe = match unsafe { narf_arch::x86_64::pmu::alloc_counter(event) } {
                    Ok(counter) => counter,
                    Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                        ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                        return;
                    }
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
                // SAFETY: release the current-CPU validation allocation.
                unsafe { narf_arch::x86_64::pmu::release(probe) };
                (Some(event), None)
            } else {
                // SAFETY: alloc_counter programs PMU hardware registers, which requires CPL=0.
                match unsafe { narf_arch::x86_64::pmu::alloc_counter(event) } {
                    Ok(counter) => (Some(event), Some(counter)),
                    Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                        ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                        return;
                    }
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
                        return;
                    }
                }
            }
        } else if attr.type_ == PERF_TYPE_SOFTWARE {
            (None, None)
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
        if pmu_event.is_none() {
            ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
            return;
        }
        let period = if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
            narf_arch::x86_64::tsc::frequency_hz()
                .max(1_000_000_000)
                .checked_div(attr.sample_period_or_freq)
                .unwrap_or(1)
                .max(1)
        } else {
            attr.sample_period_or_freq
        };
        if ensure_pmi_route().is_err() {
            if let Some(counter) = pmu_counter {
                // SAFETY: open still exclusively owns this allocation.
                unsafe { narf_arch::x86_64::pmu::release(counter) };
            }
            ctx.set_return(SyscallReturn::ok((-95i64) as u64));
            return;
        }
        let validation_counter;
        let counter = if let Some(counter) = pmu_counter.as_ref() {
            counter
        } else {
            // Task-scoped counters are allocated on switch-in, but validate
            // overflow support and the requested period synchronously.
            // SAFETY: syscall context at CPL0.
            validation_counter =
                match unsafe { narf_arch::x86_64::pmu::alloc_counter(pmu_event.unwrap()) } {
                    Ok(counter) => counter,
                    Err(_) => {
                        ctx.set_return(SyscallReturn::ok((-95i64) as u64));
                        return;
                    }
                };
            &validation_counter
        };
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
        if pmu_counter.is_none() {
            // SAFETY: task-scoped validation allocation on this CPU.
            unsafe { narf_arch::x86_64::pmu::release(*counter) };
        }
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
            inherited_tasks: IrqSafeSpinLock::new(Vec::new()),
            enabled: AtomicBool::new(false),
            count_base: AtomicU64::new(0),
            count_accumulated: AtomicU64::new(0),
            enabled_at_ns: AtomicU64::new(0),
            time_enabled_ns: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            sample_lost: AtomicU64::new(0),
            wakeup_pending: AtomicU32::new(0),
            #[cfg(target_arch = "x86_64")]
            sample_period: AtomicU64::new(sample_period),
            #[cfg(target_arch = "x86_64")]
            last_sample_period: AtomicU64::new(sample_period),
            #[cfg(target_arch = "x86_64")]
            sample_frequency: if attr.flags & PERF_ATTR_FLAG_FREQ != 0 {
                attr.sample_period_or_freq
            } else {
                0
            },
            #[cfg(target_arch = "x86_64")]
            last_sample_ns: AtomicU64::new(0),
            #[cfg(target_arch = "x86_64")]
            pmu_event,
            #[cfg(target_arch = "x86_64")]
            active_task_counters: IrqSafeSpinLock::new([None; narf_lib::percpu::MAX_CPUS]),
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
