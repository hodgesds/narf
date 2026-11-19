//! Timer-driven samples use the interrupted context, never the callback IP.
use super::*;
use narf_linux_perf_uapi::{
    PERF_ATTR_FLAG_DISABLED, PERF_COUNT_SW_CPU_CLOCK, PERF_COUNT_SW_TASK_CLOCK, PERF_RECORD_LOST,
    PERF_RECORD_MISC_USER, PERF_RECORD_SAMPLE, PERF_SAMPLE_CPU, PERF_SAMPLE_IP, PERF_SAMPLE_PERIOD,
    PERF_SAMPLE_TID, PERF_SAMPLE_TIME, PERF_TYPE_SOFTWARE,
};

struct TestIrq(u8);

impl TestIrq {
    fn new() -> Result<Self, &'static str> {
        let vector =
            narf_interrupts::vector::alloc().map_err(|_| "no software-perf test vector")?;
        narf_interrupts::install_handler_named(vector, "perf-clock-test", 0, |_| {
            narf_time::hrtimer::hrtimer_interrupt();
            narf_interrupts::IrqStatus::Handled
        });
        Ok(Self(vector))
    }

    fn fire(&self, fd: u32, user: bool) {
        self.fire_state(
            fd,
            narf_interrupts::InterruptedUserState {
                user,
                abi: 1,
                ip: 0x1234_5678,
                sp: 0,
                regs: [0; 34],
            },
        );
    }

    fn fire_state(&self, fd: u32, state: narf_interrupts::InterruptedUserState) {
        narf_lib::sync::without_interrupts(|| {
            assert!(crate::perf_event::expire_software_clock_for_test(fd));
            narf_interrupts::on_irq_with_user_state(self.0, state.ip, Some(&state));
        });
    }
}

impl Drop for TestIrq {
    fn drop(&mut self) {
        narf_interrupts::remove_handler(self.0, "perf-clock-test", 0);
        let _ = narf_interrupts::vector::free(self.0);
    }
}

fn read_word(phys: u64, offset: u64) -> u64 {
    // SAFETY: callers retain the perf file owning the aligned metadata/data
    // page and pass naturally aligned offsets wholly within that page.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(phys + offset).kernel_ptr()) }
}

fn smoke_perf_software_clock_irq_records_and_lifecycle() -> TestResult {
    with_setup(|| {
        #[cfg(target_arch = "aarch64")]
        use narf_arch::aarch64::pmu::PmuError;
        #[cfg(target_arch = "x86_64")]
        use narf_arch::x86_64::pmu::PmuError;
        if crate::perf_event::pmu_open_errno(PmuError::NoPmu) != crate::errno::ENODEV
            || crate::perf_event::pmu_open_errno(PmuError::UnsupportedEvent)
                != crate::errno::EOPNOTSUPP
            || crate::perf_event::pmu_open_errno(PmuError::NoFreeCounter) != crate::errno::EBUSY
        {
            return Err("PMU absence no longer permits upstream perf's software fallback");
        }
        let irq = TestIrq::new()?;
        for config in [PERF_COUNT_SW_CPU_CLOCK, PERF_COUNT_SW_TASK_CLOCK] {
            let attr = PerfEventAttr {
                type_: PERF_TYPE_SOFTWARE,
                size: core::mem::size_of::<PerfEventAttr>() as u32,
                config,
                sample_period_or_freq: 99,
                sample_type: PERF_SAMPLE_IP
                    | PERF_SAMPLE_TID
                    | PERF_SAMPLE_TIME
                    | PERF_SAMPLE_CPU
                    | PERF_SAMPLE_PERIOD,
                flags: PERF_ATTR_FLAG_DISABLED
                    | PERF_ATTR_FLAG_FREQ
                    | PERF_ATTR_FLAG_EXCLUDE_KERNEL,
                wakeup_events_or_watermark: 1,
                ..PerfEventAttr::default()
            };
            let fd = match call(
                Syscall::PerfEventOpen.raw(),
                a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
            ) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("software clock sampling was rejected without a PMU"),
            };
            let ops = crate::fd::with_table(FAKE_TASK, |table| {
                table.get(fd).map(|entry| entry.ops.clone())
            })
            .flatten()
            .ok_or("software clock fd missing")?;
            let frames = ops
                .mmap_frames(0, 2 * 4096)
                .map_err(|_| "software clock mmap failed")?;
            if call(
                Syscall::Ioctl.raw(),
                a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
            ) != Some(0)
            {
                return Err("software clock enable failed");
            }
            irq.fire(fd, false);
            crate::perf_event::drain_irq_samples();
            if read_word(frames[0], 1024) != 0 {
                return Err("exclude_kernel admitted a kernel timer sample");
            }
            irq.fire(fd, true);
            crate::perf_event::drain_irq_samples();
            let header = read_word(frames[1], 0);
            if read_word(frames[0], 1024) != 48
                || header as u32 != PERF_RECORD_SAMPLE
                || (header >> 32) as u16 != PERF_RECORD_MISC_USER
                || header >> 48 != 48
                || read_word(frames[1], 8) != 0x1234_5678
                || read_word(frames[1], 32) != narf_lib::percpu::current_cpu() as u64
                || read_word(frames[1], 40) != 1_000_000_000 / 99
            {
                return Err("software sample lost interrupted IP, mode, CPU or fixed ns period");
            }
            if ops.poll_readiness() & narf_filesystem::POLL_IN == 0 {
                return Err("software sample failed to publish POLLIN");
            }
            crate::perf_event::on_task_switch(FAKE_TASK, true);
            crate::perf_event::on_task_switch(FAKE_TASK, false);
            irq.fire(fd, true);
            crate::perf_event::drain_irq_samples();
            if read_word(frames[0], 1024) != 48 {
                return Err("off-CPU software clock continued sampling");
            }
            if call(
                Syscall::Ioctl.raw(),
                a2(fd as u64, PERF_EVENT_IOC_DISABLE, 0),
            ) != Some(0)
            {
                return Err("software clock disable failed");
            }
            irq.fire(fd, true);
            crate::perf_event::drain_irq_samples();
            if read_word(frames[0], 1024) != 48 {
                return Err("disabled software clock emitted another record");
            }
            let frequency = 250u64;
            if call(
                Syscall::Ioctl.raw(),
                a2(
                    fd as u64,
                    PERF_EVENT_IOC_PERIOD,
                    &frequency as *const _ as u64,
                ),
            ) != Some(0)
                || call(
                    Syscall::Ioctl.raw(),
                    a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
                ) != Some(0)
            {
                return Err("software clock frequency update failed");
            }
            irq.fire(fd, true);
            crate::perf_event::drain_irq_samples();
            if read_word(frames[1], 48 + 40) != 4_000_000 {
                return Err("software clock period ioctl did not convert Hz to ns");
            }
            let _ = call(
                Syscall::Ioctl.raw(),
                a2(fd as u64, PERF_EVENT_IOC_DISABLE, 0),
            );
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/perf_software_clock",
    smoke_perf_software_clock_irq_records_and_lifecycle
);

fn smoke_perf_software_clock_irq_queue_reports_loss() -> TestResult {
    with_setup(|| {
        let irq = TestIrq::new()?;
        let attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: PERF_COUNT_SW_CPU_CLOCK,
            sample_period_or_freq: 1_000_000_000,
            sample_type: PERF_SAMPLE_IP,
            flags: PERF_ATTR_FLAG_DISABLED,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &attr as *const _ as u64,
                -1i32 as u64,
                narf_lib::percpu::current_cpu() as u64,
                -1i32 as u64,
            ),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("software clock loss event open failed"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("software clock loss fd missing")?;
        let frames = ops
            .mmap_frames(0, 2 * 4096)
            .map_err(|_| "software loss mmap failed")?;
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        );
        for _ in 0..70 {
            irq.fire(fd, true);
        }
        crate::perf_event::drain_irq_samples();
        let header = read_word(frames[1], 0);
        if header as u32 != PERF_RECORD_LOST
            || header >> 48 != 24
            || read_word(frames[1], 16) != 6
            || read_word(frames[0], 1024) != 24 + 64 * 16
        {
            return Err("software timer ring overflow lost attribution or record count");
        }
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_DISABLE, 0),
        );
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/perf_software_clock",
    smoke_perf_software_clock_irq_queue_reports_loss
);

fn smoke_perf_records_use_linux_thread_ids() -> TestResult {
    with_setup(|| {
        use narf_linux_perf_uapi::{
            PERF_ATTR_FLAG_COMM, PERF_ATTR_FLAG_INHERIT, PERF_ATTR_FLAG_MMAP, PERF_ATTR_FLAG_TASK,
            PERF_COUNT_SW_DUMMY, PERF_RECORD_COMM, PERF_RECORD_FORK, PERF_RECORD_MMAP,
        };
        const CHILD_TASK: u64 = FAKE_TASK + 60;
        const CHILD_PID: u64 = FAKE_TASK + 58;
        const CHILD_TID: u64 = FAKE_TASK + 59;
        struct Identity;
        impl Drop for Identity {
            fn drop(&mut self) {
                crate::handlers::__test_forget_thread(CHILD_TASK);
            }
        }
        crate::handlers::__test_register_thread(CHILD_TID, CHILD_TASK, CHILD_PID);
        let _identity = Identity;
        let attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: PERF_COUNT_SW_DUMMY,
            sample_period_or_freq: 1,
            sample_type: PERF_SAMPLE_IP | PERF_SAMPLE_TID,
            flags: PERF_ATTR_FLAG_INHERIT
                | PERF_ATTR_FLAG_COMM
                | PERF_ATTR_FLAG_MMAP
                | PERF_ATTR_FLAG_TASK,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("perf identity event open failed"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("perf identity fd missing")?;
        let frames = ops
            .mmap_frames(0, 2 * 4096)
            .map_err(|_| "perf identity mmap failed")?;
        crate::perf_event::on_fork(FAKE_TASK, CHILD_PID, FAKE_TASK, CHILD_TASK);
        crate::perf_event::on_comm(CHILD_TASK, "perf-thread");
        crate::perf_event::on_mmap(CHILD_TASK, -1, 0x4000, 4096, 0, 5, 2);
        if !crate::perf_event::sample_fd_for_test(fd, CHILD_TASK, 0x4000) {
            return Err("perf identity conversion broke raw task membership");
        }
        let end = read_word(frames[0], 1024);
        let mut offset = 0;
        for kind in [
            PERF_RECORD_FORK,
            PERF_RECORD_COMM,
            PERF_RECORD_MMAP,
            PERF_RECORD_SAMPLE,
        ] {
            if offset >= end {
                return Err("perf identity sideband or sample record missing");
            }
            let header = read_word(frames[1], offset);
            if header as u32 != kind {
                return Err("perf identity record order changed");
            }
            let identity = read_word(
                frames[1],
                offset + if kind == PERF_RECORD_SAMPLE { 16 } else { 8 },
            );
            if identity as u32 != CHILD_PID as u32 {
                return Err("perf record exposed a scheduler task as Linux PID");
            }
            let tid = if kind == PERF_RECORD_FORK {
                read_word(frames[1], offset + 16) as u32
            } else {
                (identity >> 32) as u32
            };
            if tid != CHILD_TID as u32 {
                return Err("perf record exposed a scheduler task as Linux TID");
            }
            offset += header >> 48;
        }
        if offset != end {
            return Err("unexpected trailing perf identity records");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi/perf", smoke_perf_records_use_linux_thread_ids);

// Unlike the direct mmap_frames fixtures, this crosses sys_mmap's actual
// open-file access checks used by perf record/top.
fn smoke_perf_software_clock_writable_mmap_syscall() -> TestResult {
    with_setup(|| {
        install_test_address_space()?;
        let attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: PERF_COUNT_SW_CPU_CLOCK,
            sample_period_or_freq: 10_000_000,
            sample_type: PERF_SAMPLE_IP,
            flags: PERF_ATTR_FLAG_DISABLED,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("perf clock open failed"),
        };
        let mapping = call(
            Syscall::Mmap.raw(),
            SyscallArgs {
                arg0: 0,
                arg1: 8192,
                arg2: 3, // PROT_READ | PROT_WRITE
                arg3: 1, // MAP_SHARED
                arg4: fd,
                arg5: 0,
            },
        );
        let result = match mapping {
            Some(addr) if addr > 0 => {
                if call(Syscall::Munmap.raw(), a1(addr as u64, 8192)) == Some(0) {
                    Ok(())
                } else {
                    Err("perf sample ring munmap failed")
                }
            }
            _ => Err("perf sample ring writable mmap was rejected"),
        };
        let _ = call(Syscall::Close.raw(), a0(fd));
        result
    })
}
kernel_test_in!(
    "syscall_abi/perf_software_clock",
    smoke_perf_software_clock_writable_mmap_syscall
);

// Use the real IRQ producer and a poll callback: the callback must be able to
// acquire the registry, and another IRQ arriving there must survive the drain.
#[cfg(feature = "kernel-test")]
fn smoke_perf_deferred_drain_liveness() -> TestResult {
    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct WakeProbe {
        irq: Arc<TestIrq>,
        fd: u32,
        calls: AtomicUsize,
        registry_free: AtomicBool,
    }
    impl Wake for WakeProbe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            if !crate::perf_event::sample_registry_unlocked_for_test() {
                self.registry_free.store(false, Ordering::Relaxed);
            }
            if self.calls.fetch_add(1, Ordering::Relaxed) == 0 {
                self.irq.fire(self.fd, true);
            }
        }
    }

    with_setup(|| {
        let irq = Arc::new(TestIrq::new()?);
        let attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: PERF_COUNT_SW_CPU_CLOCK,
            sample_period_or_freq: 1_000_000_000,
            sample_type: PERF_SAMPLE_IP,
            flags: PERF_ATTR_FLAG_DISABLED,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("deferred clock open failed"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("deferred clock fd missing")?;
        let frames = ops.mmap_frames(0, 8192).map_err(|_| "clock mmap failed")?;
        let probe = Arc::new(WakeProbe {
            irq: irq.clone(),
            fd,
            calls: AtomicUsize::new(0),
            registry_free: AtomicBool::new(true),
        });
        let waker = core::task::Waker::from(probe.clone());
        if ops.arm_readiness(FAKE_TASK, narf_filesystem::POLL_IN, &waker)
            != Some(core::task::Poll::Pending)
        {
            return Err("empty clock ring was already readable");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("deferred clock enable failed");
        }
        irq.fire(fd, true);
        let _ = call(Syscall::GetPid.raw(), SyscallArgs::default());
        if read_word(frames[0], 1024) != 0 {
            return Err("unrelated syscall drained perf work in the caller");
        }
        crate::perf_event::drain_irq_samples();
        if probe.calls.load(Ordering::Relaxed) == 0 || !probe.registry_free.load(Ordering::Relaxed)
        {
            return Err("sample wake ran under the event registry lock");
        }
        if !crate::perf_event::sample_drain_pending_for_test() {
            return Err("IRQ publication during drain lost its next-pass notification");
        }
        crate::perf_event::drain_irq_samples();
        if read_word(frames[0], 1024) != 32 {
            return Err("racing IRQ sample was lost or duplicated");
        }
        ops.disarm_readiness(FAKE_TASK);
        // Closing the fd must also work while a consumer still retains the
        // event. Its disabled, queued sample is discarded before final drop.
        irq.fire(fd, true);
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_DISABLE, 0),
        ) != Some(0)
            || call(Syscall::Close.raw(), a0(fd as u64)) != Some(0)
        {
            return Err("closing a sampled event failed");
        }
        crate::perf_event::drain_irq_samples();
        if read_word(frames[0], 1024) != 32 {
            return Err("disabled event emitted its queued sample after close");
        }
        Ok(())
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "syscall_abi/perf_software_clock",
    smoke_perf_deferred_drain_liveness
);

#[cfg(target_arch = "x86_64")]
fn smoke_perf_x86_dwarf_register_record() -> TestResult {
    use narf_linux_perf_uapi::{
        PERF_ATTR_FLAG_EXCLUDE_CALLCHAIN_KERNEL, PERF_ATTR_FLAG_EXCLUDE_CALLCHAIN_USER,
        PERF_SAMPLE_CALLCHAIN, PERF_SAMPLE_ID, PERF_SAMPLE_READ, PERF_SAMPLE_REGS_USER,
        PERF_SAMPLE_STACK_USER, PERF_SAMPLE_WEIGHT,
    };

    with_setup(|| {
        let irq = TestIrq::new()?;
        // Upstream perf --call-graph dwarf,4096 requests this exact register
        // mask and excludes only its redundant frame-pointer user callchain.
        let mut attr = PerfEventAttr {
            type_: PERF_TYPE_SOFTWARE,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: PERF_COUNT_SW_CPU_CLOCK,
            sample_period_or_freq: 99,
            sample_type: PERF_SAMPLE_IP
                | PERF_SAMPLE_PERIOD
                | PERF_SAMPLE_CALLCHAIN
                | PERF_SAMPLE_REGS_USER
                | PERF_SAMPLE_STACK_USER
                | PERF_SAMPLE_WEIGHT,
            sample_regs_user: 0xff0fff,
            sample_stack_user: 4096,
            flags: PERF_ATTR_FLAG_DISABLED
                | PERF_ATTR_FLAG_FREQ
                | PERF_ATTR_FLAG_EXCLUDE_CALLCHAIN_USER,
            ..PerfEventAttr::default()
        };
        let open = |attr: &PerfEventAttr| {
            call(
                Syscall::PerfEventOpen.raw(),
                a3(attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
            )
        };
        for unsupported in [12, 13, 14, 15, 24, 32] {
            attr.sample_regs_user = 1u64 << unsupported;
            if open(&attr) != Some(-crate::errno::EOPNOTSUPP) {
                return Err("perf accepted an uncaptured segment/reserved/XMM register");
            }
        }
        attr.sample_regs_user = 0xff0fff;
        let fd = match open(&attr) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("upstream perf DWARF register mask/flags rejected"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| table.get(fd).map(|e| e.ops.clone()))
            .flatten()
            .ok_or("DWARF event fd missing")?;
        let frames = ops.mmap_frames(0, 8192).map_err(|_| "DWARF mmap failed")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("DWARF enable failed");
        }
        let mut regs = [0; 34];
        // The real x86 trap packs these twenty values consecutively. On the
        // wire the last eight correspond to Linux indices 16..23, not 12..19.
        let expected = [
            0xa0,
            0xb0,
            0xc0,
            0xd0,
            0x51,
            0xd1,
            0,
            0,
            0x1234_5678,
            0x202,
            0x23,
            0x1b,
            0x8888,
            0x9999,
            0xaaaa,
            0xbbbb,
            0xcccc,
            0xdddd,
            0xeeee,
            0xffff,
        ];
        regs[..20].copy_from_slice(&expected);
        irq.fire_state(
            fd,
            narf_interrupts::InterruptedUserState {
                user: true,
                abi: 1,
                ip: 0x1234_5678,
                sp: 0,
                regs,
            },
        );
        crate::perf_event::drain_irq_samples();
        // PERIOD precedes CALLCHAIN. An empty stack has no dyn_size word;
        // WEIGHT follows it immediately.
        if read_word(frames[0], 1024) != 216
            || read_word(frames[1], 0) >> 48 != 216
            || read_word(frames[1], 16) != 1_000_000_000 / 99
            || read_word(frames[1], 24) != 0 // excluded user callchain
            || read_word(frames[1], 32) != 2 // Linux ABI_64, not ABI_32
            || read_word(frames[1], 200) != 0
            || read_word(frames[1], 208) != 0
        {
            return Err("DWARF user record has wrong ABI tag/shape");
        }
        for (index, value) in expected.iter().enumerate() {
            if read_word(frames[1], 40 + index as u64 * 8) != *value {
                return Err("DWARF register values do not follow Linux x86 numbering");
            }
        }
        irq.fire(fd, false);
        crate::perf_event::drain_irq_samples();
        if read_word(frames[0], 1024) != 280
            || read_word(frames[1], 216) >> 48 != 64
            || read_word(frames[1], 232) != 1_000_000_000 / 99
            || read_word(frames[1], 240) != 1 // kernel IP retained
            || read_word(frames[1], 248) != 0x1234_5678
            || read_word(frames[1], 256) != 0 // ABI_NONE, no register words
            || read_word(frames[1], 264) != 0 // empty stack
            || read_word(frames[1], 272) != 0
        // weight
        {
            return Err("DWARF dropped or malformed a kernel-context sample");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        drop(ops);

        attr.flags =
            PERF_ATTR_FLAG_DISABLED | PERF_ATTR_FLAG_FREQ | PERF_ATTR_FLAG_EXCLUDE_CALLCHAIN_KERNEL;
        attr.sample_type = PERF_SAMPLE_IP
            | PERF_SAMPLE_ID
            | PERF_SAMPLE_PERIOD
            | PERF_SAMPLE_READ
            | PERF_SAMPLE_CALLCHAIN;
        attr.sample_regs_user = 0;
        attr.sample_stack_user = 0;
        let fd = match open(&attr) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("kernel callchain exclusion rejected"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| table.get(fd).map(|e| e.ops.clone()))
            .flatten()
            .ok_or("callchain event fd missing")?;
        let frames = ops
            .mmap_frames(0, 8192)
            .map_err(|_| "callchain mmap failed")?;
        let mut event_id = 0u64;
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ID, &mut event_id as *mut _ as u64),
        ) != Some(0)
        {
            return Err("callchain event ID query failed");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("callchain enable failed");
        }
        irq.fire(fd, true);
        crate::perf_event::drain_irq_samples();
        irq.fire(fd, false);
        crate::perf_event::drain_irq_samples();
        // ID/PERIOD must precede both the counter READ and CALLCHAIN blocks.
        if read_word(frames[0], 1024) != 104
            || read_word(frames[1], 0) >> 48 != 56
            || read_word(frames[1], 16) != event_id
            || read_word(frames[1], 24) != 1_000_000_000 / 99
            || read_word(frames[1], 40) != 1
            || read_word(frames[1], 48) != 0x1234_5678
            || read_word(frames[1], 56) >> 48 != 48
            || read_word(frames[1], 72) != event_id
            || read_word(frames[1], 80) != 1_000_000_000 / 99
            || read_word(frames[1], 96) != 0
        {
            return Err("kernel callchain exclusion suppressed user samples or kept kernel frames");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "syscall_abi/perf_software_clock",
    smoke_perf_x86_dwarf_register_record
);
