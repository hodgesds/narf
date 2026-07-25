//! Linux perf-event userspace ABI.
//!
//! Transcribed from Linux `include/uapi/linux/perf_event.h`
//! (GPL-2.0 WITH Linux-syscall-note). This crate defines wire format, not
//! NARF backend support policy.

#![no_std]

pub const PERF_TYPE_HARDWARE: u32 = 0;
pub const PERF_TYPE_SOFTWARE: u32 = 1;
pub const PERF_TYPE_TRACEPOINT: u32 = 2;
pub const PERF_TYPE_HW_CACHE: u32 = 3;
pub const PERF_TYPE_RAW: u32 = 4;
pub const PERF_TYPE_BREAKPOINT: u32 = 5;

pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
pub const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;
pub const PERF_COUNT_HW_BUS_CYCLES: u64 = 6;
pub const PERF_COUNT_HW_STALLED_CYCLES_FRONTEND: u64 = 7;
pub const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;
pub const PERF_COUNT_HW_REF_CPU_CYCLES: u64 = 9;

pub const PERF_COUNT_HW_CACHE_L1D: u64 = 0;
pub const PERF_COUNT_HW_CACHE_L1I: u64 = 1;
pub const PERF_COUNT_HW_CACHE_LL: u64 = 2;
pub const PERF_COUNT_HW_CACHE_DTLB: u64 = 3;
pub const PERF_COUNT_HW_CACHE_ITLB: u64 = 4;
pub const PERF_COUNT_HW_CACHE_BPU: u64 = 5;
pub const PERF_COUNT_HW_CACHE_NODE: u64 = 6;
pub const PERF_COUNT_HW_CACHE_OP_READ: u64 = 0;
pub const PERF_COUNT_HW_CACHE_OP_WRITE: u64 = 1;
pub const PERF_COUNT_HW_CACHE_OP_PREFETCH: u64 = 2;
pub const PERF_COUNT_HW_CACHE_RESULT_ACCESS: u64 = 0;
pub const PERF_COUNT_HW_CACHE_RESULT_MISS: u64 = 1;

pub const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
pub const PERF_COUNT_SW_PAGE_FAULTS: u64 = 2;
pub const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
pub const PERF_COUNT_SW_CPU_MIGRATIONS: u64 = 4;
pub const PERF_COUNT_SW_PAGE_FAULTS_MIN: u64 = 5;
pub const PERF_COUNT_SW_PAGE_FAULTS_MAJ: u64 = 6;
pub const PERF_COUNT_SW_ALIGNMENT_FAULTS: u64 = 7;
pub const PERF_COUNT_SW_EMULATION_FAULTS: u64 = 8;
pub const PERF_COUNT_SW_DUMMY: u64 = 9;
pub const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
pub const PERF_COUNT_SW_CGROUP_SWITCHES: u64 = 11;

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_READ: u64 = 1 << 4;
pub const PERF_SAMPLE_CALLCHAIN: u64 = 1 << 5;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;
pub const PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_SAMPLE_BRANCH_STACK: u64 = 1 << 11;
pub const PERF_SAMPLE_REGS_USER: u64 = 1 << 12;
pub const PERF_SAMPLE_STACK_USER: u64 = 1 << 13;
pub const PERF_SAMPLE_WEIGHT: u64 = 1 << 14;
pub const PERF_SAMPLE_DATA_SRC: u64 = 1 << 15;
pub const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;
pub const PERF_SAMPLE_TRANSACTION: u64 = 1 << 17;
pub const PERF_SAMPLE_REGS_INTR: u64 = 1 << 18;
pub const PERF_SAMPLE_PHYS_ADDR: u64 = 1 << 19;
pub const PERF_SAMPLE_AUX: u64 = 1 << 20;
pub const PERF_SAMPLE_CGROUP: u64 = 1 << 21;
pub const PERF_SAMPLE_DATA_PAGE_SIZE: u64 = 1 << 22;
pub const PERF_SAMPLE_CODE_PAGE_SIZE: u64 = 1 << 23;
pub const PERF_SAMPLE_WEIGHT_STRUCT: u64 = 1 << 24;

pub const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
pub const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
pub const PERF_FORMAT_ID: u64 = 1 << 2;
pub const PERF_FORMAT_GROUP: u64 = 1 << 3;
pub const PERF_FORMAT_LOST: u64 = 1 << 4;

pub const PERF_ATTR_FLAG_DISABLED: u64 = 1 << 0;
pub const PERF_ATTR_FLAG_INHERIT: u64 = 1 << 1;
pub const PERF_ATTR_FLAG_PINNED: u64 = 1 << 2;
pub const PERF_ATTR_FLAG_EXCLUSIVE: u64 = 1 << 3;
pub const PERF_ATTR_FLAG_EXCLUDE_USER: u64 = 1 << 4;
pub const PERF_ATTR_FLAG_EXCLUDE_KERNEL: u64 = 1 << 5;
pub const PERF_ATTR_FLAG_EXCLUDE_HV: u64 = 1 << 6;
pub const PERF_ATTR_FLAG_EXCLUDE_IDLE: u64 = 1 << 7;
pub const PERF_ATTR_FLAG_MMAP: u64 = 1 << 8;
pub const PERF_ATTR_FLAG_COMM: u64 = 1 << 9;
pub const PERF_ATTR_FLAG_FREQ: u64 = 1 << 10;
pub const PERF_ATTR_FLAG_INHERIT_STAT: u64 = 1 << 11;
pub const PERF_ATTR_FLAG_ENABLE_ON_EXEC: u64 = 1 << 12;
pub const PERF_ATTR_FLAG_TASK: u64 = 1 << 13;
pub const PERF_ATTR_FLAG_WATERMARK: u64 = 1 << 14;
pub const PERF_ATTR_FLAG_PRECISE_IP_MASK: u64 = 3 << 15;
pub const PERF_ATTR_FLAG_MMAP_DATA: u64 = 1 << 17;
pub const PERF_ATTR_FLAG_SAMPLE_ID_ALL: u64 = 1 << 18;
pub const PERF_ATTR_FLAG_EXCLUDE_GUEST: u64 = 1 << 20;
pub const PERF_ATTR_FLAG_MMAP2: u64 = 1 << 23;
pub const PERF_ATTR_FLAG_COMM_EXEC: u64 = 1 << 24;
pub const PERF_ATTR_FLAG_KSYMBOL: u64 = 1 << 29;
pub const PERF_ATTR_FLAG_BPF_EVENT: u64 = 1 << 30;
pub const PERF_ATTR_FLAG_BUILD_ID: u64 = 1 << 34;

pub const PERF_ATTR_SIZE_VER0: u32 = 64;
pub const PERF_ATTR_SIZE_VER1: u32 = 72;
pub const PERF_ATTR_SIZE_VER2: u32 = 80;
pub const PERF_ATTR_SIZE_VER3: u32 = 96;
pub const PERF_ATTR_SIZE_VER4: u32 = 104;
pub const PERF_ATTR_SIZE_VER5: u32 = 112;
pub const PERF_ATTR_SIZE_VER6: u32 = 120;
pub const PERF_ATTR_SIZE_VER7: u32 = 128;
pub const PERF_ATTR_SIZE_VER8: u32 = 136;
pub const PERF_ATTR_SIZE_VER9: u32 = 144;

pub const PERF_RECORD_MMAP: u32 = 1;
pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_COMM: u32 = 3;
pub const PERF_RECORD_EXIT: u32 = 4;
pub const PERF_RECORD_THROTTLE: u32 = 5;
pub const PERF_RECORD_UNTHROTTLE: u32 = 6;
pub const PERF_RECORD_FORK: u32 = 7;
pub const PERF_RECORD_READ: u32 = 8;
pub const PERF_RECORD_SAMPLE: u32 = 9;
pub const PERF_RECORD_MMAP2: u32 = 10;
pub const PERF_RECORD_LOST_SAMPLES: u32 = 13;

pub const PERF_RECORD_MISC_CPUMODE_MASK: u16 = 7;
pub const PERF_RECORD_MISC_KERNEL: u16 = 1;
pub const PERF_RECORD_MISC_USER: u16 = 2;
pub const PERF_RECORD_MISC_MMAP_DATA: u16 = 1 << 13;
pub const PERF_RECORD_MISC_COMM_EXEC: u16 = 1 << 13;
pub const PERF_RECORD_MISC_EXACT_IP: u16 = 1 << 14;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PerfEventHeader {
    pub type_: u32,
    pub misc: u16,
    pub size: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct PerfEventAttr {
    pub type_: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub bp_addr_or_config1: u64,
    pub bp_len_or_config2: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
    pub sig_data: u64,
    pub config3: u64,
    pub config4: u64,
}

const _: () = {
    assert!(core::mem::size_of::<PerfEventHeader>() == 8);
    assert!(core::mem::size_of::<PerfEventAttr>() == PERF_ATTR_SIZE_VER9 as usize);
    assert!(core::mem::offset_of!(PerfEventAttr, config) == 8);
    assert!(core::mem::offset_of!(PerfEventAttr, flags) == 40);
    assert!(core::mem::offset_of!(PerfEventAttr, sig_data) == 120);
    assert!(core::mem::offset_of!(PerfEventAttr, config3) == 128);
    assert!(core::mem::offset_of!(PerfEventAttr, config4) == 136);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_perf_uapi_layout_and_values() {
        assert_eq!(core::mem::size_of::<PerfEventHeader>(), 8);
        assert_eq!(
            core::mem::size_of::<PerfEventAttr>(),
            PERF_ATTR_SIZE_VER9 as usize
        );
        assert_eq!(core::mem::offset_of!(PerfEventAttr, flags), 40);
        assert_eq!(core::mem::offset_of!(PerfEventAttr, config4), 136);
        assert_eq!(PERF_SAMPLE_IDENTIFIER, 1 << 16);
        assert_eq!(PERF_RECORD_SAMPLE, 9);
        assert_eq!(PERF_RECORD_MMAP2, 10);
    }
}
