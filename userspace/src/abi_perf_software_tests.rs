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
        narf_lib::sync::without_interrupts(|| {
            assert!(crate::perf_event::expire_software_clock_for_test(fd));
            let state = narf_interrupts::InterruptedUserState {
                user,
                abi: 1,
                ip: 0x1234_5678,
                sp: 0,
                regs: [0; 34],
            };
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
